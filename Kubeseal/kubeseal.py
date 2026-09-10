# Kubeseal Sublime Text plugin
#
# Best-practice notes (Sublime API / porting guide):
# - No sublime.* API calls at import time (plugin_host loads async)
# - Buffer mutations only inside TextCommand.run(edit, ...)
# - Background work via threading; UI / view edits via sublime.set_timeout
# - Stage selection via Window.show_quick_panel
# - Settings via load_settings + edit_settings (default package + User overlay)
# - Paths expanded with sublime.expand_variables (${home}, ${packages}, ...)
#
# Compatible with Sublime Text 3/4 plugin host (Python 3.3+): no f-strings.

import sublime
import sublime_plugin
import subprocess
import threading
import os
import re
import json
import base64


# ---------------------------------------------------------------------------
# Module state (no API at import)
# ---------------------------------------------------------------------------

_operation_lock = threading.Lock()
_operation_active = False


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable without Sublime)
# ---------------------------------------------------------------------------

_RFC1123_NAME = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')
_RFC1123_DNS = re.compile(
    r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$'
)


def b64decode_to_text(value):
    """Decode a base64 string to UTF-8 text. Returns original value on failure."""
    if value is None or not isinstance(value, str):
        return value
    stripped = value.strip().strip('"').strip("'")
    if not stripped:
        return value
    try:
        # validate= not available on older plugin-host Pythons
        raw = base64.b64decode(stripped)
    except Exception:
        return value
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('utf-8', errors='replace')


def _yaml_escape_scalar(text):
    """Quote a YAML scalar when needed so decoded plaintext stays valid YAML."""
    if text is None:
        return '""'
    if text == '':
        return '""'
    needs_quote = (
        text[0] in ' \t' or text[-1] in ' \t'
        or any(ch in text for ch in ':#{}[]&*!|>\'"%@`,?\n\r')
        or text.lower() in ('true', 'false', 'null', 'yes', 'no', '~')
        or re.match(r'^[-0-9]', text)
    )
    if not needs_quote:
        return text
    return json.dumps(text)


def decode_secret_data_fields(content):
    """
    After kubeseal --recovery-unseal, Secret.data values are still base64.
    Decode every key under data (e.g. data.data) for human-readable output.
    Supports JSON (kubeseal default) and simple YAML.
    """
    if not content or not content.strip():
        return content

    stripped = content.strip()

    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError):
        obj = None

    if isinstance(obj, dict) and isinstance(obj.get('data'), dict):
        decoded = {}
        for key, val in obj['data'].items():
            decoded[key] = b64decode_to_text(val) if isinstance(val, str) else val
        obj['data'] = decoded
        return json.dumps(obj, indent=2, ensure_ascii=False) + '\n'

    return _decode_secret_data_yamlish(content)


def _decode_secret_data_yamlish(content):
    lines = content.split('\n')
    result = []
    in_data = False
    data_indent = None

    for line in lines:
        if re.match(r'^data:\s*$', line):
            in_data = True
            data_indent = None
            result.append(line)
            continue

        if in_data:
            if re.match(r'^\s*#', line) or line.strip() == '':
                result.append(line)
                continue

            m = re.match(r'^(\s*)([^:\s][^:]*):\s*(.*)$', line)
            if not m:
                in_data = False
                result.append(line)
                continue

            indent, key, val = m.group(1), m.group(2), m.group(3)
            indent_len = len(indent)

            if data_indent is None:
                data_indent = indent_len

            if indent_len < data_indent:
                in_data = False
                result.append(line)
                continue

            if indent_len == data_indent and val.strip() != '':
                decoded = b64decode_to_text(val.strip())
                result.append('{}{}: {}'.format(indent, key, _yaml_escape_scalar(decoded)))
                continue

            result.append(line)
            continue

        result.append(line)

    return '\n'.join(result)


def derive_sealedsecret_output_path(input_path):
    """
    Map an open template file to its sealed output path.

    Examples:
      foo-secret-template.yaml  -> foo-sealedsecret.yaml
      foo-secret-template       -> foo-sealedsecret.yaml
      foo-template.yaml         -> foo-sealedsecret.yaml
      foo.yaml                  -> foo-sealedsecret.yaml
    """
    directory = os.path.dirname(input_path)
    basename = os.path.basename(input_path)
    name, _ext = os.path.splitext(basename)

    if name.endswith('-secret-template'):
        out_name = name[: -len('-secret-template')] + '-sealedsecret.yaml'
    elif name.endswith('-template'):
        out_name = name[: -len('-template')] + '-sealedsecret.yaml'
    else:
        out_name = name + '-sealedsecret.yaml'

    return os.path.join(directory, out_name)


def build_full_seal_command(cert_path):
    """kubeseal command for sealing a whole Secret manifest (stdin -> stdout)."""
    return ['kubeseal', '--format=yaml', '--cert', cert_path]


def looks_like_sealed_secret(content):
    """Heuristic: buffer already looks like a SealedSecret (do not re-seal)."""
    if not content:
        return False
    head = content[:2000]
    return bool(re.search(r'(?m)^kind:\s*SealedSecret\s*$', head)) or (
        '"kind"' in head and 'SealedSecret' in head
    )


def looks_like_plain_secret(content):
    """Heuristic: buffer looks like a core/v1 Secret suitable for full-file seal."""
    if not content:
        return False
    head = content[:4000]
    has_secret_kind = bool(re.search(r'(?m)^kind:\s*Secret\s*$', head)) or (
        '"kind"' in head and re.search(r'"kind"\s*:\s*"Secret"', head)
    )
    return has_secret_kind and not looks_like_sealed_secret(content)


def looks_like_already_encrypted_blob(text):
    """Heuristic: selection already looks like kubeseal --raw output."""
    if not text:
        return False
    s = text.strip()
    # SealedSecrets raw ciphertext is typically long base64-ish starting with Ag
    if len(s) < 80:
        return False
    if s.startswith('Ag') and re.match(r'^[A-Za-z0-9+/=]+$', s):
        return True
    return False


def validate_k8s_dns_label(value, field_name):
    """Return error string or None. RFC 1123 subdomain / label checks."""
    if not value:
        return '{} cannot be empty'.format(field_name)
    if len(value) > 253:
        return '{} is too long (max 253)'.format(field_name)
    if not _RFC1123_DNS.match(value):
        return (
            '{} must be a valid DNS subdomain (lowercase alphanumeric and \'-\', '
            'e.g. my-namespace)'.format(field_name)
        )
    return None


def normalize_stages(raw_stages):
    """Normalize settings stages list into dicts with name/cert/key."""
    stages = []
    if not isinstance(raw_stages, list):
        return stages
    for item in raw_stages:
        if not isinstance(item, dict):
            continue
        name = (item.get('name') or item.get('stage') or '').strip()
        if not name:
            continue
        stages.append({
            'name': name,
            'cert_path': (item.get('cert_path') or item.get('public_key_path') or '').strip(),
            'private_key_path': (item.get('private_key_path') or '').strip(),
            'description': (item.get('description') or '').strip(),
        })
    return stages


def guess_stage_index(file_path, stages):
    """
    Prefer a stage whose name appears as a path segment
    (e.g. .../environments/dev/my-cluster/... → my-cluster).
    """
    if not file_path or not stages:
        return -1
    norm = file_path.replace('\\', '/')
    parts = norm.split('/')
    # Exact cluster folder match first
    for i, stage in enumerate(stages):
        name = stage['name']
        if name in parts:
            return i
    # Partial: stage name contained in path
    for i, stage in enumerate(stages):
        if '/{}/'.format(stage['name']) in '/{}/'.format(norm.strip('/')):
            return i
    return -1


def stage_requires_cert(stage):
    return bool(stage and stage.get('cert_path'))


def stage_requires_key(stage):
    return bool(stage and stage.get('private_key_path'))


def find_kubeseal_binary():
    """Return absolute path to kubeseal or None."""
    path_env = os.environ.get('PATH', '')
    # GUI apps on macOS often lack Homebrew PATH — include common locations
    extras = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin']
    search_dirs = path_env.split(os.pathsep) + extras
    seen = set()
    for d in search_dirs:
        if not d or d in seen:
            continue
        seen.add(d)
        candidate = os.path.join(d, 'kubeseal')
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        # Windows
        candidate_exe = candidate + '.exe'
        if os.path.isfile(candidate_exe):
            return candidate_exe
    return None


# ---------------------------------------------------------------------------
# Sublime helpers
# ---------------------------------------------------------------------------

def _expand_path(path):
    """Expand ${home}/${packages}/~ and normalize."""
    if not path:
        return ''
    try:
        variables = {}
        # window.extract_variables() is nicer but we may have no window yet
        variables['home'] = os.path.expanduser('~')
        variables['packages'] = sublime.packages_path()
        try:
            variables['installed_packages'] = sublime.installed_packages_path()
        except Exception:
            pass
        path = sublime.expand_variables(path, variables)
    except Exception:
        pass
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    return os.path.normpath(path)


def _set_operation_active(active):
    global _operation_active
    with _operation_lock:
        _operation_active = active


def _is_operation_active():
    with _operation_lock:
        return _operation_active


class KubesealCommand(sublime_plugin.TextCommand):
    """Base class for kubeseal operations"""

    def get_settings(self):
        settings = sublime.load_settings('Kubeseal.sublime-settings')
        stages = normalize_stages(settings.get('stages', []))
        # Expand paths in stages
        for stage in stages:
            stage['cert_path'] = _expand_path(stage.get('cert_path', ''))
            stage['private_key_path'] = _expand_path(stage.get('private_key_path', ''))

        legacy_cert = _expand_path(settings.get('cert_path', '') or '')
        legacy_key = _expand_path(settings.get('private_key_path', '') or '')

        # Backward compatible: inject legacy single-key as a synthetic stage
        if not stages and (legacy_cert or legacy_key):
            stages = [{
                'name': 'default',
                'cert_path': legacy_cert,
                'private_key_path': legacy_key,
                'description': 'Legacy cert_path / private_key_path',
            }]

        return {
            'stages': stages,
            'default_stage': (settings.get('default_stage') or '').strip(),
            'ask_stage_every_time': settings.get('ask_stage_every_time', True),
            'last_stage': (settings.get('last_stage') or '').strip(),
            'timeout': int(settings.get('timeout', 30) or 30),
            'decrypt_output': settings.get('decrypt_output', 'new_tab'),
            'default_namespace': settings.get('default_namespace', 'default'),
            'default_secret_name': settings.get('default_secret_name', 'mysecret'),
            'max_selections': int(settings.get('max_selections', 10) or 10),
            'decode_secret_data': settings.get('decode_secret_data', True),
            'validate_k8s_names': settings.get('validate_k8s_names', True),
            'confirm_overwrite_sealedsecret': settings.get('confirm_overwrite_sealedsecret', True),
            'confirm_reseal_selection': settings.get('confirm_reseal_selection', True),
            'kubeseal_path': _expand_path(settings.get('kubeseal_path', '') or ''),
            # keep legacy fields for validate / fallbacks
            'cert_path': legacy_cert,
            'private_key_path': legacy_key,
        }

    def show_error(self, message):
        sublime.error_message('Kubeseal Error: {}'.format(message))

    def show_status(self, message):
        sublime.status_message('Kubeseal: {}'.format(message))

    def remember_stage(self, stage_name):
        settings = sublime.load_settings('Kubeseal.sublime-settings')
        settings.set('last_stage', stage_name)
        sublime.save_settings('Kubeseal.sublime-settings')

    def resolve_kubeseal(self):
        configured = self.settings.get('kubeseal_path') if hasattr(self, 'settings') else ''
        if configured:
            if os.path.isfile(configured) and os.access(configured, os.X_OK):
                return configured
            return None
        return find_kubeseal_binary()

    def extract_metadata_from_file(self):
        """Extract namespace and secret name from current file's YAML metadata."""
        try:
            file_content = self.view.substr(sublime.Region(0, self.view.size()))
            namespace = None
            secret_name = None
            namespace_pattern = r'^\s*namespace:\s*[\'"]?([^\s\'"#]+)[\'"]?'
            name_pattern = r'^\s*name:\s*[\'"]?([^\s\'"#]+)[\'"]?'
            in_metadata = False

            for line in file_content.split('\n'):
                if re.match(r'^\s*metadata:\s*$', line):
                    in_metadata = True
                    continue
                if in_metadata and re.match(r'^[a-zA-Z]', line):
                    in_metadata = False
                if in_metadata:
                    namespace_match = re.match(namespace_pattern, line)
                    if namespace_match:
                        namespace = namespace_match.group(1).strip()
                    name_match = re.match(name_pattern, line)
                    if name_match:
                        secret_name = name_match.group(1).strip()
            return namespace, secret_name
        except Exception:
            return None, None

    def _run_kubeseal(self, cmd, input_text, timeout):
        """Run kubeseal synchronously; returns (stdout, stderr, returncode)."""
        # Avoid leaking secrets into crash dumps via argv — paths only, data on stdin
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        try:
            try:
                stdout, stderr = process.communicate(input=input_text, timeout=timeout)
            except TypeError:
                stdout, stderr = process.communicate(input=input_text)
        except Exception as e:
            try:
                process.kill()
            except Exception:
                pass
            timeout_exc = getattr(subprocess, 'TimeoutExpired', None)
            if timeout_exc is not None and isinstance(e, timeout_exc):
                return '', 'kubeseal timed out after {}s'.format(timeout), -1
            raise
        return stdout, stderr, process.returncode

    def _begin_operation(self):
        if _is_operation_active():
            self.show_error(
                'Another Kubeseal operation is already running. Wait for it to finish.'
            )
            return False
        _set_operation_active(True)
        return True

    def _end_operation(self):
        _set_operation_active(False)

    def pick_stage(self, need_cert, need_private_key, on_picked):
        """
        Show quick panel of stages. on_picked(stage_dict) or not called on cancel.
        Filters out stages missing required key files when possible; still lists
        them with a warning so the user sees misconfiguration.
        """
        stages = self.settings.get('stages') or []
        if not stages:
            self.show_error(
                'No stages configured. Add a "stages" list in Kubeseal settings '
                '(name, cert_path, private_key_path).'
            )
            return

        file_name = self.view.file_name()
        guessed = guess_stage_index(file_name, stages)

        default_name = self.settings.get('last_stage') or self.settings.get('default_stage')
        selected_index = 0
        if guessed >= 0:
            selected_index = guessed
        elif default_name:
            for i, s in enumerate(stages):
                if s['name'] == default_name:
                    selected_index = i
                    break

        # Single stage + ask_stage_every_time false → skip panel
        if len(stages) == 1 and not self.settings.get('ask_stage_every_time', True):
            stage = stages[0]
            err = self._validate_stage_paths(stage, need_cert, need_private_key)
            if err:
                self.show_error(err)
                return
            on_picked(stage)
            return

        if not self.settings.get('ask_stage_every_time', True) and default_name:
            for s in stages:
                if s['name'] == default_name:
                    err = self._validate_stage_paths(s, need_cert, need_private_key)
                    if err:
                        self.show_error(err)
                        return
                    on_picked(s)
                    return

        items = []
        for s in stages:
            cert_ok = s.get('cert_path') and os.path.isfile(s['cert_path'])
            key_ok = s.get('private_key_path') and os.path.isfile(s['private_key_path'])
            flags = []
            if need_cert:
                flags.append('cert {}'.format('OK' if cert_ok else 'MISSING'))
            if need_private_key:
                flags.append('key {}'.format('OK' if key_ok else 'MISSING'))
            if not need_cert and not need_private_key:
                flags.append('cert {}'.format('OK' if cert_ok else '—'))
                flags.append('key {}'.format('OK' if key_ok else '—'))
            detail = s.get('description') or ', '.join(flags)
            if s.get('description') and flags:
                detail = '{}  ({})'.format(s['description'], ', '.join(flags))
            items.append([s['name'], detail])

        window = self.view.window()
        if not window:
            self.show_error('No active window')
            return

        def on_select(index):
            if index < 0:
                self.show_status('Cancelled')
                return
            stage = stages[index]
            err = self._validate_stage_paths(stage, need_cert, need_private_key)
            if err:
                self.show_error(err)
                return
            self.remember_stage(stage['name'])
            on_picked(stage)

        placeholder = 'Select sealed-secrets stage / cluster key'
        try:
            window.show_quick_panel(
                items, on_select, 0, selected_index, None, placeholder
            )
        except TypeError:
            # Older API without placeholder
            window.show_quick_panel(items, on_select, 0, selected_index)

    def _validate_stage_paths(self, stage, need_cert, need_private_key):
        if need_cert:
            path = stage.get('cert_path') or ''
            if not path:
                return 'Stage "{}" has no cert_path (public key) configured'.format(stage['name'])
            if not os.path.isfile(path):
                return 'Stage "{}" cert not found:\n{}'.format(stage['name'], path)
            if not os.access(path, os.R_OK):
                return 'Stage "{}" cert is not readable:\n{}'.format(stage['name'], path)
        if need_private_key:
            path = stage.get('private_key_path') or ''
            if not path:
                return (
                    'Stage "{}" has no private_key_path configured '
                    '(required for decrypt / recovery-unseal)'
                ).format(stage['name'])
            if not os.path.isfile(path):
                return 'Stage "{}" private key not found:\n{}'.format(stage['name'], path)
            if not os.access(path, os.R_OK):
                return 'Stage "{}" private key is not readable:\n{}'.format(stage['name'], path)
        return None


# ---------------------------------------------------------------------------
# Encrypt / full-file seal
# ---------------------------------------------------------------------------

class KubesealEncryptCommand(KubesealCommand):
    """
    Encrypt:
      - with selection: kubeseal --raw (replace selection in place)
      - without selection: seal entire open file to sibling *-sealedsecret.yaml
    Always asks which stage key/cert to use (unless ask_stage_every_time=false).
    """

    def is_enabled(self):
        return self.view is not None and not self.view.is_read_only()

    def is_visible(self):
        return True

    def run(self, edit):
        if self.view.is_read_only():
            self.show_error('View is read-only')
            return

        self.settings = self.get_settings()
        self._mode = None
        self.stage = None
        self.regions = []

        has_selection = any(not r.empty() for r in self.view.sel())
        self._mode = 'raw' if has_selection else 'file'

        if self._mode == 'file':
            err = self._precheck_full_file_seal()
            if err:
                self.show_error(err)
                return

        self.pick_stage(
            need_cert=True,
            need_private_key=False,
            on_picked=self._on_stage_picked_for_encrypt
        )

    def _precheck_full_file_seal(self):
        file_name = self.view.file_name()
        if not file_name:
            return (
                'Save the file first (needed to derive *-sealedsecret.yaml output path), '
                'or select text for raw encrypt.'
            )
        content = self.view.substr(sublime.Region(0, self.view.size()))
        if not content.strip():
            return 'File is empty — nothing to seal'
        if looks_like_sealed_secret(content):
            return (
                'This file looks like a SealedSecret already. '
                'Refusing to seal it again (would nest ciphertext).'
            )
        if not looks_like_plain_secret(content):
            return (
                'Full-file seal expects a Kubernetes Secret manifest (kind: Secret). '
                'Select a string for raw encrypt, or open a Secret template.'
            )
        output_path = derive_sealedsecret_output_path(file_name)
        if os.path.abspath(output_path) == os.path.abspath(file_name):
            return 'Refusing to overwrite the source file with sealed output'
        return None

    def _on_stage_picked_for_encrypt(self, stage):
        self.stage = stage
        self.settings['cert_path'] = stage['cert_path']
        self.show_status('Using stage: {}'.format(stage['name']))

        if self._mode == 'file':
            self._seal_entire_file()
            return

        namespace, secret_name = self.extract_metadata_from_file()
        if namespace and secret_name:
            if self.settings.get('validate_k8s_names', True):
                for field, val in (('namespace', namespace), ('secret name', secret_name)):
                    err = validate_k8s_dns_label(val, field)
                    if err:
                        self.show_error(err)
                        return
            self.show_status(
                'Using metadata from file: namespace={}, name={}'.format(namespace, secret_name)
            )
            self.proceed_with_encryption(namespace, secret_name)
        else:
            self.show_status('No metadata found in file, prompting for values...')
            window = self.view.window()
            if not window:
                self.show_error('No active window')
                return
            self.window = window
            window.show_input_panel(
                'Enter namespace:',
                self.settings.get('default_namespace', 'default'),
                self.on_namespace_entered,
                None,
                None
            )

    def _seal_entire_file(self):
        file_name = self.view.file_name()
        output_path = derive_sealedsecret_output_path(file_name)
        file_content = self.view.substr(sublime.Region(0, self.view.size()))

        if self.view.is_dirty():
            self.show_status('Buffer has unsaved changes — sealing current buffer contents')

        if os.path.exists(output_path) and self.settings.get('confirm_overwrite_sealedsecret', True):
            ok = sublime.ok_cancel_dialog(
                'Output file already exists:\n\n{}\n\nOverwrite?'.format(output_path),
                'Overwrite'
            )
            if not ok:
                self.show_status('Cancelled')
                return

        kubeseal = self.resolve_kubeseal()
        if not kubeseal:
            self.show_error(
                'kubeseal binary not found. Install it or set kubeseal_path in settings.'
            )
            return

        if not self._begin_operation():
            return

        self.show_status(
            '[{}] Sealing entire file → {}'.format(
                self.stage['name'], os.path.basename(output_path)
            )
        )
        threading.Thread(
            target=self._seal_file_async,
            args=(kubeseal, file_content, output_path)
        ).start()

    def _seal_file_async(self, kubeseal, file_content, output_path):
        try:
            cmd = [kubeseal] + build_full_seal_command(self.settings['cert_path'])[1:]
            sealed, error, returncode = self._run_kubeseal(
                cmd, file_content, self.settings.get('timeout', 30)
            )

            def done():
                try:
                    if returncode != 0:
                        self.show_error('Full-file seal failed: {}'.format(error or 'unknown error'))
                        return
                    if not sealed.strip() or 'SealedSecret' not in sealed:
                        self.show_error(
                            'kubeseal returned unexpected output (no SealedSecret). '
                            'stderr: {}'.format(error or '(empty)')
                        )
                        return
                    try:
                        with open(output_path, 'w', encoding='utf-8') as fh:
                            fh.write(sealed if sealed.endswith('\n') else sealed + '\n')
                    except Exception as e:
                        self.show_error('Failed to write {}: {}'.format(output_path, e))
                        return

                    window = self.view.window()
                    if window:
                        window.open_file(output_path)
                    self.show_status(
                        '[{}] Sealed secret written: {}'.format(
                            self.stage['name'], output_path
                        )
                    )
                finally:
                    self._end_operation()

            sublime.set_timeout(done, 0)

        except Exception as e:
            def fail():
                self._end_operation()
                self.show_error('Full-file seal failed: {}'.format(str(e)))
            sublime.set_timeout(fail, 0)

    def on_namespace_entered(self, namespace):
        self.namespace = (namespace or '').strip()
        if not self.namespace:
            self.show_error('Namespace cannot be empty')
            return
        if self.settings.get('validate_k8s_names', True):
            err = validate_k8s_dns_label(self.namespace, 'namespace')
            if err:
                self.show_error(err)
                return
        self.window.show_input_panel(
            'Enter secret name:',
            self.settings.get('default_secret_name', 'mysecret'),
            self.on_secret_name_entered,
            None,
            None
        )

    def on_secret_name_entered(self, secret_name):
        self.secret_name = (secret_name or '').strip()
        if not self.secret_name:
            self.show_error('Secret name cannot be empty')
            return
        if self.settings.get('validate_k8s_names', True):
            err = validate_k8s_dns_label(self.secret_name, 'secret name')
            if err:
                self.show_error(err)
                return
        self.proceed_with_encryption(self.namespace, self.secret_name)

    def proceed_with_encryption(self, namespace, secret_name):
        max_sel = self.settings.get('max_selections', 10)
        self.regions = []
        for region in self.view.sel():
            if region.empty():
                continue
            text = self.view.substr(region)
            if not text:
                continue
            if looks_like_already_encrypted_blob(text) and self.settings.get(
                'confirm_reseal_selection', True
            ):
                ok = sublime.ok_cancel_dialog(
                    'Selection looks like it is already kubeseal --raw ciphertext.\n\n'
                    'Encrypting again will nest/corrupt it. Continue anyway?',
                    'Encrypt anyway'
                )
                if not ok:
                    self.show_status('Cancelled')
                    return
            self.regions.append({
                'start': region.begin(),
                'end': region.end(),
                'expected': text,
            })
            if len(self.regions) >= max_sel:
                break

        if not self.regions:
            self.show_error('No non-empty selection to encrypt')
            return

        kubeseal = self.resolve_kubeseal()
        if not kubeseal:
            self.show_error(
                'kubeseal binary not found. Install it or set kubeseal_path in settings.'
            )
            return

        if not self._begin_operation():
            return

        self.show_status('[{}] Encrypting...'.format(self.stage['name']))
        threading.Thread(
            target=self._encrypt_all_async,
            args=(kubeseal, namespace, secret_name)
        ).start()

    def _encrypt_all_async(self, kubeseal, namespace, secret_name):
        """Encrypt all selections off-UI, then apply replacements in one edit."""
        results = []
        try:
            for item in self.regions:
                cmd = [
                    kubeseal, '--raw',
                    '--cert', self.settings['cert_path'],
                    '--namespace', namespace,
                    '--name', secret_name,
                ]
                encrypted, error, returncode = self._run_kubeseal(
                    cmd, item['expected'], self.settings.get('timeout', 30)
                )
                if returncode != 0:
                    results.append({'error': error or 'encryption failed'})
                    break
                results.append({
                    'start': item['start'],
                    'end': item['end'],
                    'expected': item['expected'],
                    'new_text': encrypted.strip(),
                })

            def done():
                try:
                    if results and 'error' in results[-1] and 'new_text' not in results[-1]:
                        self.show_error('Encryption failed: {}'.format(results[-1]['error']))
                        return
                    # Apply reverse-order so offsets stay valid (ST edit best practice)
                    self.view.run_command('kubeseal_replace_regions', {
                        'replacements': [r for r in results if 'new_text' in r]
                    })
                    self.show_status(
                        '[{}] Encrypted {} selection(s)'.format(
                            self.stage['name'], len(results)
                        )
                    )
                finally:
                    self._end_operation()

            sublime.set_timeout(done, 0)
        except Exception as e:
            def fail():
                self._end_operation()
                self.show_error('Encryption failed: {}'.format(str(e)))
            sublime.set_timeout(fail, 0)


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

class KubesealDecryptCommand(KubesealCommand):
    """Decrypt sealed secret using private key (offline)."""

    def is_enabled(self):
        if self.view is None:
            return False
        return any(not r.empty() for r in self.view.sel())

    def run(self, edit):
        self.settings = self.get_settings()

        selected_text = ''
        for region in self.view.sel():
            if not region.empty():
                selected_text = self.view.substr(region)
                break

        if not selected_text.strip():
            self.show_error('Please select encrypted text to decrypt')
            return

        # Safety: selection should look like ciphertext, not a whole YAML doc by mistake
        if '\n' in selected_text.strip() and 'kind:' in selected_text:
            ok = sublime.ok_cancel_dialog(
                'Selection looks like a full YAML document, not a single encrypted blob.\n\n'
                'Raw decrypt expects the ciphertext string only. Continue anyway?',
                'Continue'
            )
            if not ok:
                return

        self.selected_encrypted_text = selected_text.strip()
        self.pick_stage(
            need_cert=False,
            need_private_key=True,
            on_picked=self._on_stage_picked_for_decrypt
        )

    def _on_stage_picked_for_decrypt(self, stage):
        self.stage = stage
        self.settings['private_key_path'] = stage['private_key_path']
        self.show_status('Using stage: {}'.format(stage['name']))

        namespace, secret_name = self.extract_metadata_from_file()
        if namespace and secret_name:
            if self.settings.get('validate_k8s_names', True):
                for field, val in (('namespace', namespace), ('secret name', secret_name)):
                    err = validate_k8s_dns_label(val, field)
                    if err:
                        self.show_error(err)
                        return
            self.show_status(
                'Using metadata from file: namespace={}, name={}'.format(namespace, secret_name)
            )
            self.proceed_with_decryption(namespace, secret_name)
        else:
            window = self.view.window()
            if not window:
                self.show_error('No active window')
                return
            self.window = window
            window.show_input_panel(
                'Enter namespace (used during encryption):',
                self.settings.get('default_namespace', 'default'),
                self.on_decrypt_namespace_entered,
                None,
                None
            )

    def on_decrypt_namespace_entered(self, namespace):
        self.namespace = (namespace or '').strip()
        if not self.namespace:
            self.show_error('Namespace cannot be empty')
            return
        if self.settings.get('validate_k8s_names', True):
            err = validate_k8s_dns_label(self.namespace, 'namespace')
            if err:
                self.show_error(err)
                return
        self.window.show_input_panel(
            'Enter secret name (used during encryption):',
            self.settings.get('default_secret_name', 'mysecret'),
            self.on_decrypt_secret_name_entered,
            None,
            None
        )

    def on_decrypt_secret_name_entered(self, secret_name):
        self.secret_name = (secret_name or '').strip()
        if not self.secret_name:
            self.show_error('Secret name cannot be empty')
            return
        if self.settings.get('validate_k8s_names', True):
            err = validate_k8s_dns_label(self.secret_name, 'secret name')
            if err:
                self.show_error(err)
                return
        self.proceed_with_decryption(self.namespace, self.secret_name)

    def proceed_with_decryption(self, namespace, secret_name):
        kubeseal = self.resolve_kubeseal()
        if not kubeseal:
            self.show_error(
                'kubeseal binary not found. Install it or set kubeseal_path in settings.'
            )
            return
        if not self._begin_operation():
            return

        self.show_status('[{}] Decrypting...'.format(self.stage['name']))
        threading.Thread(
            target=self._decrypt_async,
            args=(kubeseal, self.selected_encrypted_text, namespace, secret_name)
        ).start()

    def _decrypt_async(self, kubeseal, encrypted_text, namespace, secret_name):
        try:
            sealed_secret_yaml = self._create_sealed_secret_yaml(
                encrypted_text, namespace, secret_name
            )
            cmd = [
                kubeseal,
                '--recovery-unseal',
                '--recovery-private-key', self.settings['private_key_path'],
            ]
            decrypted_output, error, returncode = self._run_kubeseal(
                cmd, sealed_secret_yaml, self.settings.get('timeout', 30)
            )

            def done():
                try:
                    self._handle_decrypt_result(
                        decrypted_output, error, returncode, namespace, secret_name
                    )
                finally:
                    self._end_operation()

            sublime.set_timeout(done, 0)
        except Exception as e:
            def fail():
                self._end_operation()
                self.show_error('Decryption failed: {}'.format(str(e)))
            sublime.set_timeout(fail, 0)

    def _create_sealed_secret_yaml(self, encrypted_text, namespace, secret_name):
        # Guard against YAML injection breaking the wrapper document
        if re.search(r'[\n\r]', encrypted_text):
            raise ValueError('Encrypted blob must be a single line')
        yaml_content = (
            'apiVersion: bitnami.com/v1alpha1\n'
            'kind: SealedSecret\n'
            'metadata:\n'
            '  name: {name}\n'
            '  namespace: {namespace}\n'
            'spec:\n'
            '  encryptedData:\n'
            '    data: {encrypted_data}\n'
            '  template:\n'
            '    metadata:\n'
            '      name: {name}\n'
            '      namespace: {namespace}\n'
        ).format(
            encrypted_data=encrypted_text,
            name=secret_name,
            namespace=namespace,
        )
        return yaml_content

    def _handle_decrypt_result(self, decrypted_output, error, return_code, namespace, secret_name):
        if return_code != 0:
            self.show_error('Decryption failed: {}'.format(error or 'unknown error'))
            return
        if not decrypted_output.strip():
            self.show_error('Decryption returned empty output')
            return

        content = decrypted_output
        if self.settings.get('decode_secret_data', True):
            content = decode_secret_data_fields(decrypted_output)

        # Mark scratch buffer so user is less likely to save plaintext into git by accident
        if self.settings.get('decrypt_output') == 'popup':
            self._show_in_popup(content, namespace, secret_name)
        else:
            self._show_in_new_tab(content, namespace, secret_name)

        decoded_note = (
            'data fields base64-decoded' if self.settings.get('decode_secret_data', True)
            else 'raw Secret'
        )
        self.show_status(
            '[{}] Decryption completed ({})'.format(self.stage['name'], decoded_note)
        )

    def _show_in_new_tab(self, content, namespace, secret_name):
        window = self.view.window()
        if not window:
            self.show_error('No active window')
            return
        new_view = window.new_file()
        stage = self.stage['name'] if self.stage else '?'
        new_view.set_name('Decrypted [{}]: {}/{}'.format(stage, namespace, secret_name))
        new_view.set_scratch(True)  # avoid accidental save prompts / git commits
        if content.lstrip().startswith('{'):
            try:
                new_view.set_syntax_file('Packages/JSON/JSON.sublime-syntax')
            except Exception:
                try:
                    new_view.set_syntax_file('Packages/JavaScript/JSON.sublime-syntax')
                except Exception:
                    new_view.set_syntax_file('Packages/YAML/YAML.sublime-syntax')
        else:
            new_view.set_syntax_file('Packages/YAML/YAML.sublime-syntax')
        new_view.run_command('kubeseal_insert_content', {'content': content})

    def _show_in_popup(self, content, namespace, secret_name):
        # Cap popup size — huge secrets freeze UI
        display = content
        max_chars = 8000
        if len(display) > max_chars:
            display = display[:max_chars] + '\n… [truncated]'
        popup_content = (
            '<body>'
            '<style>'
            'body {{ font-family: monospace; font-size: 12px; }}'
            '.header {{ color: #569cd6; font-weight: bold; margin-bottom: 10px; }}'
            '.content {{ background: #1e1e1e; color: #d4d4d4; padding: 10px; white-space: pre-wrap; }}'
            '</style>'
            '<div class="header">Decrypted Secret: {}/{}</div>'
            '<div class="content">{}</div>'
            '</body>'
        ).format(
            namespace,
            secret_name,
            display.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'),
        )
        self.view.show_popup(
            popup_content,
            flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
            max_width=800,
            max_height=600,
        )


# ---------------------------------------------------------------------------
# Helper text commands (required: only TextCommand may own Edit objects)
# ---------------------------------------------------------------------------

class KubesealReplaceTextCommand(sublime_plugin.TextCommand):
    def run(self, edit, region_start, region_end, new_text):
        region = sublime.Region(region_start, region_end)
        self.view.replace(edit, region, new_text)


class KubesealReplaceRegionsCommand(sublime_plugin.TextCommand):
    """
    Apply multiple replacements safely:
    - reverse order by start offset (length changes don't invalidate earlier regions)
    - skip / abort if buffer text no longer matches expected snapshot
    """

    def run(self, edit, replacements):
        if not replacements:
            return
        ordered = sorted(replacements, key=lambda r: r['start'], reverse=True)
        skipped = 0
        for item in ordered:
            region = sublime.Region(item['start'], item['end'])
            current = self.view.substr(region)
            if current != item.get('expected', current):
                skipped += 1
                continue
            self.view.replace(edit, region, item['new_text'])
        if skipped:
            sublime.error_message(
                'Kubeseal: {} selection(s) were skipped because the buffer changed '
                'during encryption. Re-select and try again.'.format(skipped)
            )


class KubesealInsertContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, content):
        self.view.insert(edit, 0, content)


# ---------------------------------------------------------------------------
# Config / settings commands
# ---------------------------------------------------------------------------

class KubesealValidateConfigCommand(sublime_plugin.ApplicationCommand):
    def run(self):
        settings = sublime.load_settings('Kubeseal.sublime-settings')
        stages = normalize_stages(settings.get('stages', []))
        for stage in stages:
            stage['cert_path'] = _expand_path(stage.get('cert_path', ''))
            stage['private_key_path'] = _expand_path(stage.get('private_key_path', ''))

        problems = []
        kubeseal_path = _expand_path(settings.get('kubeseal_path', '') or '')
        binary = kubeseal_path if kubeseal_path and os.path.isfile(kubeseal_path) else find_kubeseal_binary()
        version = None
        if not binary:
            problems.append('kubeseal binary not found in PATH (set kubeseal_path if needed)')
        else:
            try:
                proc = subprocess.Popen(
                    [binary, '--version'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                out, err = proc.communicate()
                version = (out or err or '').strip() or 'unknown'
            except Exception as e:
                problems.append('Failed to run kubeseal: {}'.format(e))

        if not stages:
            legacy_cert = _expand_path(settings.get('cert_path', '') or '')
            legacy_key = _expand_path(settings.get('private_key_path', '') or '')
            if not legacy_cert and not legacy_key:
                problems.append('No stages configured and no legacy cert_path/private_key_path')
            else:
                if legacy_cert and not os.path.isfile(legacy_cert):
                    problems.append('legacy cert_path not found: {}'.format(legacy_cert))
                if legacy_key and not os.path.isfile(legacy_key):
                    problems.append('legacy private_key_path not found: {}'.format(legacy_key))
        else:
            for s in stages:
                if s.get('cert_path') and not os.path.isfile(s['cert_path']):
                    problems.append('[{}] cert missing: {}'.format(s['name'], s['cert_path']))
                if s.get('private_key_path') and not os.path.isfile(s['private_key_path']):
                    problems.append(
                        '[{}] private key missing: {}'.format(s['name'], s['private_key_path'])
                    )
                if not s.get('cert_path') and not s.get('private_key_path'):
                    problems.append('[{}] has neither cert_path nor private_key_path'.format(s['name']))

        if problems:
            sublime.error_message(
                'Kubeseal configuration problems:\n- ' + '\n- '.join(problems)
            )
        else:
            stage_lines = []
            for s in stages:
                stage_lines.append(
                    '  {}  cert={}  key={}'.format(
                        s['name'],
                        'yes' if s.get('cert_path') and os.path.isfile(s['cert_path']) else 'no',
                        'yes' if s.get('private_key_path') and os.path.isfile(s['private_key_path']) else 'no',
                    )
                )
            sublime.message_dialog(
                'Kubeseal configuration OK.\n\nkubeseal: {}\n\nStages:\n{}'.format(
                    version or binary,
                    '\n'.join(stage_lines) if stage_lines else '(legacy single key)',
                )
            )


class KubesealOpenSettingsCommand(sublime_plugin.ApplicationCommand):
    """Open default + User settings side-by-side (Sublime edit_settings pattern)."""

    def run(self):
        sublime.run_command('edit_settings', {
            'base_file': '${packages}/Kubeseal/Kubeseal.sublime-settings',
            'default': (
                '{\n'
                '\t"stages": [\n'
                '\t\t{\n'
                '\t\t\t"name": "dev",\n'
                '\t\t\t"cert_path": "${home}/path/to/sealed-secrets/pub.pem",\n'
                '\t\t\t"private_key_path": "${home}/path/to/sealed-secrets/priv.key"\n'
                '\t\t}\n'
                '\t]\n'
                '}\n'
            ),
        })

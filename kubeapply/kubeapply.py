import fnmatch
import os
import re
import subprocess
import tempfile
import threading

import sublime
import sublime_plugin


# Common cluster-scoped kinds (Kind only). Unknown kinds are treated as
# namespaced so the plugin asks for a namespace when metadata.namespace is missing.
CLUSTER_SCOPED_KINDS = {
    "APIService",
    "CertificateSigningRequest",
    "ClusterIssuer",
    "ClusterRole",
    "ClusterRoleBinding",
    "ComponentStatus",
    "CSIDriver",
    "CSINode",
    "CustomResourceDefinition",
    "FlowSchema",
    "IngressClass",
    "MutatingWebhookConfiguration",
    "Namespace",
    "Node",
    "PersistentVolume",
    "PriorityClass",
    "PriorityLevelConfiguration",
    "RuntimeClass",
    "StorageClass",
    "ValidatingAdmissionPolicy",
    "ValidatingAdmissionPolicyBinding",
    "ValidatingWebhookConfiguration",
    "VolumeAttachment",
}


def _settings():
    s = sublime.load_settings("Kubeapply.sublime-settings")
    return {
        "kubectl_path": s.get("kubectl_path", "kubectl") or "kubectl",
        "timeout": int(s.get("timeout", 60) or 60),
        "always_pass_context": bool(s.get("always_pass_context", True)),
        "dry_run_before_apply": bool(s.get("dry_run_before_apply", True)),
        "show_diff_before_apply": bool(s.get("show_diff_before_apply", True)),
        "require_confirmation": bool(s.get("require_confirmation", True)),
        "dangerous_context_patterns": list(
            s.get(
                "dangerous_context_patterns",
                ["*prod*", "*production*", "*-prod-*", "prod-*"],
            )
            or []
        ),
        "dangerous_context_require_type_name": bool(
            s.get("dangerous_context_require_type_name", True)
        ),
        "warn_unsaved_buffer": bool(s.get("warn_unsaved_buffer", True)),
        "namespace_picker": s.get("namespace_picker", "quick_panel") or "quick_panel",
        "default_namespace": s.get("default_namespace", "default") or "default",
        "allow_force": bool(s.get("allow_force", False)),
        "validate": bool(s.get("validate", True)),
        "server_side_apply": bool(s.get("server_side_apply", False)),
        "field_manager": s.get("field_manager", "sublime-kubeapply")
        or "sublime-kubeapply",
        "show_result_in_tab": bool(s.get("show_result_in_tab", True)),
    }


def _run_kubectl(args, settings, stdin_data=None):
    """Run kubectl; returns (returncode, stdout, stderr)."""
    cmd = [settings["kubectl_path"]] + list(args)
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate(
            input=stdin_data, timeout=settings["timeout"]
        )
        return process.returncode, stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            pass
        return 124, "", "kubectl timed out after {}s".format(settings["timeout"])
    except FileNotFoundError:
        return 127, "", "kubectl not found: {}".format(settings["kubectl_path"])
    except Exception as exc:
        return 1, "", str(exc)


def _is_dangerous_context(context, patterns):
    ctx = (context or "").lower()
    for pattern in patterns or []:
        if fnmatch.fnmatch(ctx, pattern.lower()):
            return True
    return False


def _parse_resources(content):
    """
    Lightweight multi-doc YAML parse for kind / name / namespace.
    Avoids a PyYAML dependency (not bundled with Sublime).
    """
    resources = []
    # Split on document markers at line start
    docs = re.split(r"(?m)^---\s*$", content or "")
    for idx, doc in enumerate(docs):
        text = doc.strip()
        if not text or text.startswith("..."):
            continue

        kind = None
        name = None
        namespace = None
        api_version = None

        in_metadata = False
        metadata_indent = None

        for raw_line in text.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue

            # Top-level keys only (no leading whitespace)
            top = re.match(r"^(apiVersion|kind|metadata)\s*:\s*(.*)$", raw_line)
            if top:
                key = top.group(1)
                value = top.group(2).strip().strip("\"'")
                if key == "apiVersion":
                    api_version = value or None
                    in_metadata = False
                elif key == "kind":
                    kind = value or None
                    in_metadata = False
                elif key == "metadata":
                    in_metadata = True
                    metadata_indent = None
                continue

            if in_metadata:
                # Leave metadata when indentation returns to top-level key
                if re.match(r"^[A-Za-z]", raw_line):
                    in_metadata = False
                    continue

                indent_match = re.match(r"^(\s+)(\S.*?)\s*:\s*(.*)$", raw_line)
                if not indent_match:
                    continue
                indent, key, value = indent_match.groups()
                indent_len = len(indent.replace("\t", "  "))
                if metadata_indent is None:
                    metadata_indent = indent_len
                # Only direct children of metadata (not labels/annotations nested)
                if indent_len != metadata_indent:
                    continue
                value = value.strip().strip("\"'")
                if key == "name" and value:
                    name = value
                elif key == "namespace" and value:
                    namespace = value

        if not kind and not name and not api_version:
            continue

        resources.append(
            {
                "index": idx,
                "apiVersion": api_version,
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "cluster_scoped": (kind in CLUSTER_SCOPED_KINDS) if kind else False,
            }
        )
    return resources


def _resource_label(resource, fallback_ns=None):
    kind = resource.get("kind") or "?"
    name = resource.get("name") or "?"
    if resource.get("cluster_scoped"):
        return "{}/{}".format(kind, name)
    ns = resource.get("namespace") or fallback_ns or "?"
    return "{}/{}/{}".format(ns, kind, name)


def _is_missing_namespace_error(text):
    """True when kubectl failed because the target namespace does not exist."""
    t = (text or "").lower()
    # Error from server (NotFound): namespaces "foo" not found
    # … error when creating "…": namespaces "foo" not found
    if re.search(r'namespaces?\s+"[^"]+"\s+not\s+found', t):
        return True
    if re.search(r"namespaces?\s+[a-z0-9]([-a-z0-9]*[a-z0-9])?\s+not\s+found", t):
        return True
    return False


def _is_resource_not_found(text):
    """True when the named resource is missing (not when its namespace is missing)."""
    combined = (text or "").lower()
    if _is_missing_namespace_error(combined):
        return False
    return "notfound" in combined.replace(" ", "") or "not found" in combined


def _write_temp_manifest(content, suffix=".yaml"):
    fd, path = tempfile.mkstemp(prefix="kubeapply-", suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            if content and not content.endswith("\n"):
                handle.write("\n")
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise
    return path


def _inject_namespace_into_manifest(content, namespace, target_kinds_names):
    """
    Insert metadata.namespace into documents that lacked it.

    Prefer mutating the temp YAML over `kubectl -n`, which can surprise
    multi-doc files that already declare other namespaces.
    target_kinds_names: set of (kind, name) pairs to patch.
    """
    if not namespace or not target_kinds_names:
        return content

    # parts: [pre, '---', doc, '---', doc, ...]
    parts = re.split(r"(?m)^(---\s*)$", content or "")
    if len(parts) == 1:
        return _inject_ns_one_doc(parts[0], namespace, target_kinds_names)

    out = []
    for chunk in parts:
        if re.match(r"^---\s*$", chunk or ""):
            out.append(chunk if chunk.endswith("\n") else chunk + "\n")
            continue
        out.append(_inject_ns_one_doc(chunk, namespace, target_kinds_names))
    return "".join(out)


def _inject_ns_one_doc(doc, namespace, target_kinds_names):
    if not doc or not doc.strip():
        return doc

    kind = None
    name = None
    has_namespace = False
    in_metadata = False
    metadata_indent = None
    metadata_line_idx = None
    name_line_idx = None
    lines = doc.splitlines(True)  # keepends

    for idx, raw_line in enumerate(lines):
        stripped = raw_line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        top = re.match(r"^(apiVersion|kind|metadata)\s*:\s*(.*)$", raw_line)
        if top:
            key = top.group(1)
            value = top.group(2).strip().strip("\"'")
            if key == "kind":
                kind = value or None
                in_metadata = False
            elif key == "metadata":
                in_metadata = True
                metadata_indent = None
                metadata_line_idx = idx
            else:
                in_metadata = False
            continue

        if in_metadata:
            if re.match(r"^[A-Za-z]", raw_line):
                in_metadata = False
                continue
            m = re.match(r"^(\s+)(\S.*?)\s*:\s*(.*)$", raw_line)
            if not m:
                continue
            indent, key, value = m.groups()
            indent_len = len(indent.replace("\t", "  "))
            if metadata_indent is None:
                metadata_indent = indent_len
            if indent_len != metadata_indent:
                continue
            value = value.strip().strip("\"'")
            if key == "name":
                name = value or None
                name_line_idx = idx
            elif key == "namespace" and value:
                has_namespace = True

    if has_namespace or (kind, name) not in target_kinds_names:
        return doc
    if metadata_line_idx is None:
        return doc

    indent = "  "
    if metadata_indent:
        indent = " " * metadata_indent
    ns_line = "{}namespace: {}\n".format(indent, namespace)
    insert_at = (name_line_idx + 1) if name_line_idx is not None else (metadata_line_idx + 1)
    lines.insert(insert_at, ns_line)
    return "".join(lines)


class _KubeapplyFlow(object):
    """Shared apply / dry-run / diff workflow."""

    MODE_APPLY = "apply"
    MODE_DRY_RUN = "dry-run"
    MODE_DIFF = "diff"

    def __init__(self, window, view, mode):
        self.window = window
        self.view = view
        self.mode = mode
        self.settings = _settings()
        self.manifest_text = ""
        self.manifest_path = None
        self.temp_path = None
        self.resources = []
        self.context = None
        self.current_context = None
        self.contexts = []
        self.namespaces = []
        self.pending_ns_resources = []
        self.chosen_namespace = None
        self.exists_summary = []
        self.diff_text = ""
        self.dry_run_text = ""
        self.missing_namespaces = []
        self.created_namespaces = []

    def start(self):
        if self.view is None:
            sublime.error_message("Kubeapply: no active view")
            return

        if self.view.size() == 0:
            sublime.error_message("Kubeapply: current file is empty")
            return

        self.manifest_text = self.view.substr(sublime.Region(0, self.view.size()))
        self.resources = _parse_resources(self.manifest_text)
        if not self.resources:
            sublime.error_message(
                "Kubeapply: no Kubernetes resources found "
                "(need apiVersion / kind / metadata.name)"
            )
            return

        missing = []
        for res in self.resources:
            if not res.get("kind"):
                missing.append("document #{}: missing kind".format(res["index"] + 1))
            if not res.get("name"):
                missing.append(
                    "document #{} ({}): missing metadata.name".format(
                        res["index"] + 1, res.get("kind") or "?"
                    )
                )
            if not res.get("apiVersion"):
                missing.append(
                    "document #{} ({}): missing apiVersion".format(
                        res["index"] + 1, res.get("kind") or "?"
                    )
                )
        if missing:
            sublime.error_message(
                "Kubeapply: invalid manifest\n\n" + "\n".join(missing[:12])
            )
            return

        if self.settings["warn_unsaved_buffer"] and self.view.is_dirty():
            # Never use ok_cancel_dialog here: dismissing a native sheet and then
            # opening a quick_panel hard-exits ST4 on macOS.
            self._confirm_quick(
                "Continue (apply unsaved buffer)",
                "Buffer has unsaved changes — Kubeapply uses buffer contents, not the on-disk file.",
                self._prepare_manifest_and_load_contexts,
            )
            return

        self._prepare_manifest_and_load_contexts()

    def _prepare_manifest_and_load_contexts(self):
        file_name = self.view.file_name()
        if file_name and not self.view.is_dirty():
            self.manifest_path = file_name
        else:
            try:
                self.temp_path = _write_temp_manifest(self.manifest_text)
                self.manifest_path = self.temp_path
            except Exception as exc:
                sublime.error_message(
                    "Kubeapply: failed to write temp manifest: {}".format(exc)
                )
                return

        sublime.status_message("Kubeapply: loading contexts...")
        threading.Thread(target=self._load_contexts_async).start()

    def _confirm_quick(self, yes_caption, detail, on_yes, on_no=None):
        """Yes/No via quick_panel (safe on macOS ST4; native dialogs are not)."""
        items = [
            [yes_caption, detail],
            ["Cancel", "Abort Kubeapply"],
        ]

        def picked(index):
            if index == 0:
                on_yes()
            else:
                if on_no is not None:
                    on_no()
                else:
                    self._on_cancel()

        # Defer so we never stack UI transitions in the same event turn.
        sublime.set_timeout(
            lambda: self.window.show_quick_panel(items, picked),
            10,
        )

    def cleanup(self):
        if self.temp_path and os.path.exists(self.temp_path):
            try:
                os.remove(self.temp_path)
            except Exception:
                pass
            self.temp_path = None

    def _kubectl(self, args, stdin_data=None):
        return _run_kubectl(args, self.settings, stdin_data=stdin_data)

    def _with_context(self, args):
        out = list(args)
        if self.settings["always_pass_context"] and self.context:
            out.extend(["--context", self.context])
        return out

    def _load_contexts_async(self):
        code, out, err = self._kubectl(["config", "get-contexts", "-o", "name"])
        code_cur, out_cur, _ = self._kubectl(["config", "current-context"])
        current = out_cur.strip() if code_cur == 0 else None

        def done():
            if code != 0:
                self.cleanup()
                sublime.error_message(
                    "Kubeapply: failed to list contexts\n\n{}".format(err or out)
                )
                return
            contexts = [line.strip() for line in out.splitlines() if line.strip()]
            if not contexts:
                self.cleanup()
                sublime.error_message("Kubeapply: no kubectl contexts found")
                return
            self.contexts = contexts
            self.current_context = current
            self._show_context_picker()

        sublime.set_timeout(done, 0)

    def _show_context_picker(self):
        items = []
        for ctx in self.contexts:
            mark = " (current)" if ctx == self.current_context else ""
            danger = ""
            if _is_dangerous_context(ctx, self.settings["dangerous_context_patterns"]):
                danger = " ⚠ PROD?"
            items.append([ctx + mark + danger, "kubectl context"])

        sublime.status_message("Kubeapply: choose context")
        self.window.show_quick_panel(items, self._on_context_chosen)

    def _on_context_chosen(self, index):
        if index < 0:
            self.cleanup()
            sublime.status_message("Kubeapply: cancelled")
            return
        self.context = self.contexts[index]

        if _is_dangerous_context(
            self.context, self.settings["dangerous_context_patterns"]
        ):
            if self.settings["dangerous_context_require_type_name"]:
                self.window.show_input_panel(
                    "Dangerous context. Type the context name to continue:",
                    "",
                    self._on_danger_context_typed,
                    None,
                    self._on_cancel,
                )
                return
            self._confirm_quick(
                "Continue with '{}'".format(self.context),
                "Context name looks like production.",
                self._after_context_ready,
            )
            return

        self._after_context_ready()

    def _on_danger_context_typed(self, typed):
        if (typed or "").strip() != self.context:
            self.cleanup()
            sublime.error_message(
                "Kubeapply: context name did not match. Aborting."
            )
            return
        self._after_context_ready()

    def _on_cancel(self):
        self.cleanup()
        sublime.status_message("Kubeapply: cancelled")

    def _after_context_ready(self):
        # Collect namespaced resources missing metadata.namespace
        self.pending_ns_resources = [
            r
            for r in self.resources
            if not r.get("cluster_scoped") and not r.get("namespace")
        ]
        if not self.pending_ns_resources:
            self._ensure_target_namespaces()
            return

        sublime.status_message("Kubeapply: loading namespaces...")
        threading.Thread(target=self._load_namespaces_async).start()

    def _load_namespaces_async(self):
        code, out, err = self._kubectl(
            self._with_context(["get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"])
        )

        def done():
            if code == 0 and out.strip():
                self.namespaces = sorted(out.strip().split())
            else:
                self.namespaces = []
            self._prompt_namespace()

        sublime.set_timeout(done, 0)

    def _prompt_namespace(self):
        kinds = sorted(
            {
                (r.get("kind") or "?")
                for r in self.pending_ns_resources
            }
        )
        prompt_note = (
            "Namespace required for: {}\n"
            "(not set in metadata.namespace)"
        ).format(", ".join(kinds))

        if (
            self.settings["namespace_picker"] == "quick_panel"
            and self.namespaces
        ):
            items = [["» Type a namespace…", prompt_note]]
            default = self.settings["default_namespace"]
            # Put default first when present
            ordered = list(self.namespaces)
            if default in ordered:
                ordered.remove(default)
                ordered.insert(0, default)
            for ns in ordered:
                items.append([ns, prompt_note])
            self.window.show_quick_panel(items, self._on_namespace_picked)
            return

        self.window.show_input_panel(
            "Namespace (missing in manifest):",
            self.settings["default_namespace"],
            self._on_namespace_typed,
            None,
            self._on_cancel,
        )

    def _on_namespace_picked(self, index):
        if index < 0:
            self._on_cancel()
            return
        if index == 0:
            self.window.show_input_panel(
                "Namespace (missing in manifest):",
                self.settings["default_namespace"],
                self._on_namespace_typed,
                None,
                self._on_cancel,
            )
            return
        # index 0 is "Type…", so namespaces start at 1
        default = self.settings["default_namespace"]
        ordered = list(self.namespaces)
        if default in ordered:
            ordered.remove(default)
            ordered.insert(0, default)
        self.chosen_namespace = ordered[index - 1]
        self._apply_chosen_namespace()

    def _on_namespace_typed(self, value):
        ns = (value or "").strip()
        if not ns:
            self.cleanup()
            sublime.error_message("Kubeapply: namespace cannot be empty")
            return
        if not re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", ns):
            self.cleanup()
            sublime.error_message(
                "Kubeapply: invalid namespace DNS label: {}".format(ns)
            )
            return
        self.chosen_namespace = ns
        self._apply_chosen_namespace()

    def _apply_chosen_namespace(self):
        targets = set()
        for res in self.pending_ns_resources:
            res["namespace"] = self.chosen_namespace
            res["namespace_from_prompt"] = True
            targets.add((res.get("kind"), res.get("name")))

        # Rewrite a temp manifest with namespace injected (do not use kubectl -n
        # on multi-doc files — it can override namespaces already in YAML).
        try:
            patched = _inject_namespace_into_manifest(
                self.manifest_text, self.chosen_namespace, targets
            )
            if self.temp_path and os.path.exists(self.temp_path):
                os.remove(self.temp_path)
            self.temp_path = _write_temp_manifest(patched)
            self.manifest_path = self.temp_path
            self.manifest_text = patched
        except Exception as exc:
            self.cleanup()
            sublime.error_message(
                "Kubeapply: failed to inject namespace into manifest: {}".format(exc)
            )
            return

        self._ensure_target_namespaces()

    def _required_namespaces(self):
        names = set()
        for res in self.resources:
            if res.get("cluster_scoped"):
                continue
            ns = res.get("namespace") or self.chosen_namespace
            if ns:
                names.add(ns)
        return sorted(names)

    def _ensure_target_namespaces(self):
        """Verify namespaces exist; prompt to create any that are missing."""
        required = self._required_namespaces()
        if not required:
            self._begin_safety_checks()
            return
        sublime.status_message("Kubeapply: checking namespaces...")
        threading.Thread(
            target=self._check_namespaces_async, args=(required,)
        ).start()

    def _check_namespaces_async(self, required):
        missing = []
        errors = []
        for ns in required:
            code, out, err = self._kubectl(
                self._with_context(["get", "namespace", ns, "-o", "name"])
            )
            if code == 0:
                continue
            msg = (err or out or "").strip()
            if _is_resource_not_found(msg) or _is_missing_namespace_error(msg):
                missing.append(ns)
            else:
                errors.append("namespace {}: {}".format(ns, msg or "unknown error"))

        def done():
            if errors:
                self._abort_with_report(
                    errors,
                    "Kubeapply: could not verify namespace(s) — see report tab",
                )
                return
            self.missing_namespaces = list(missing)
            self._prompt_next_missing_namespace()

        sublime.set_timeout(done, 0)

    def _prompt_next_missing_namespace(self):
        if not self.missing_namespaces:
            self._begin_safety_checks()
            return

        ns = self.missing_namespaces[0]

        def on_no():
            self.cleanup()
            sublime.status_message(
                "Kubeapply: cancelled — namespace '{}' missing".format(ns)
            )

        def on_yes():
            sublime.status_message("Kubeapply: creating namespace {}...".format(ns))
            threading.Thread(target=self._create_namespace_async, args=(ns,)).start()

        self._confirm_quick(
            "Create namespace '{}'".format(ns),
            "Does not exist on context '{}'. Create it, then continue {}.".format(
                self.context, self.mode
            ),
            on_yes,
            on_no=on_no,
        )

    def _create_namespace_async(self, ns):
        code, out, err = self._kubectl(
            self._with_context(["create", "namespace", ns])
        )

        def done():
            msg = (err or out or "").strip()
            if code != 0 and "already exists" not in msg.lower():
                self._abort_with_report(
                    ["Failed to create namespace {}: {}".format(ns, msg)],
                    "Kubeapply: failed to create namespace — see report tab",
                )
                return
            if self.missing_namespaces and self.missing_namespaces[0] == ns:
                self.missing_namespaces.pop(0)
            if ns not in self.created_namespaces:
                self.created_namespaces.append(ns)
            if ns not in self.namespaces:
                self.namespaces.append(ns)
            sublime.status_message("Kubeapply: namespace {} ready".format(ns))
            self._prompt_next_missing_namespace()

        sublime.set_timeout(done, 0)

    def _abort_with_report(self, errors, status_msg):
        """
        Show a report tab and abort.

        IMPORTANT: never call sublime.error_message / message_dialog / ok_cancel_dialog
        around window.new_file() — native sheets hard-exit ST4 on macOS.
        """
        self._show_output_tab(
            "Kubeapply Blocked @ {}".format(self.context),
            self._format_report(errors),
        )
        self.cleanup()
        sublime.status_message(status_msg)

    def _begin_safety_checks(self):
        sublime.status_message("Kubeapply: checking live cluster state...")
        threading.Thread(target=self._safety_checks_async).start()

    def _safety_checks_async(self):
        exists_summary = []
        errors = []

        for res in self.resources:
            kind = res["kind"]
            name = res["name"]
            args = ["get", kind, name, "-o", "name"]
            if not res.get("cluster_scoped"):
                ns = res.get("namespace") or self.chosen_namespace
                if ns:
                    args.extend(["-n", ns])
            code, out, err = self._kubectl(self._with_context(args))
            if code == 0:
                exists_summary.append(
                    {
                        "resource": res,
                        "exists": True,
                        "label": _resource_label(res, self.chosen_namespace),
                    }
                )
            else:
                msg = (err or out or "").strip()
                if _is_missing_namespace_error(msg):
                    # Should have been handled earlier; treat as hard error
                    exists_summary.append(
                        {
                            "resource": res,
                            "exists": None,
                            "label": _resource_label(res, self.chosen_namespace),
                            "error": msg,
                        }
                    )
                    errors.append(
                        "{}: {}".format(
                            _resource_label(res, self.chosen_namespace),
                            msg or "namespace missing",
                        )
                    )
                elif _is_resource_not_found(msg):
                    exists_summary.append(
                        {
                            "resource": res,
                            "exists": False,
                            "label": _resource_label(res, self.chosen_namespace),
                        }
                    )
                else:
                    # Could be unknown kind / auth — record and continue cautiously
                    exists_summary.append(
                        {
                            "resource": res,
                            "exists": None,
                            "label": _resource_label(res, self.chosen_namespace),
                            "error": msg,
                        }
                    )
                    errors.append(
                        "{}: {}".format(
                            _resource_label(res, self.chosen_namespace),
                            msg or "unknown error",
                        )
                    )

        diff_text = ""
        dry_run_text = ""

        if self.mode in (self.MODE_APPLY, self.MODE_DIFF) and self.settings[
            "show_diff_before_apply"
        ]:
            diff_args = ["diff", "-f", self.manifest_path]
            dcode, dout, derr = self._kubectl(self._with_context(diff_args))
            # kubectl diff: 0 = no diff, 1 = differences, >1 = error
            if dcode in (0, 1):
                diff_text = dout or "(no differences — live object matches manifest)"
            else:
                diff_text = "kubectl diff failed (rc={}):\n{}".format(
                    dcode, derr or dout
                )

        if self.mode == self.MODE_APPLY and self.settings["dry_run_before_apply"]:
            dry_args = self._build_apply_args(dry_run=True)
            drcode, drout, drerr = self._kubectl(self._with_context(dry_args))
            if drcode == 0:
                dry_run_text = drout.strip() or "(dry-run ok)"
            else:
                dry_run_text = ""
                errors.append("dry-run failed:\n{}".format(drerr or drout))

        if self.mode == self.MODE_DRY_RUN:
            dry_args = self._build_apply_args(dry_run=True)
            drcode, drout, drerr = self._kubectl(self._with_context(dry_args))
            dry_run_text = drout if drcode == 0 else (drerr or drout)
            if drcode != 0:
                errors.append("dry-run failed (rc={})".format(drcode))

        if self.mode == self.MODE_DIFF and not diff_text:
            diff_args = ["diff", "-f", self.manifest_path]
            dcode, dout, derr = self._kubectl(self._with_context(diff_args))
            if dcode in (0, 1):
                diff_text = dout or "(no differences)"
            else:
                diff_text = derr or dout
                errors.append("diff failed (rc={})".format(dcode))

        self.exists_summary = exists_summary
        self.diff_text = diff_text
        self.dry_run_text = dry_run_text

        def done():
            if self.mode == self.MODE_DIFF:
                self._show_output_tab(
                    "Kubeapply Diff @ {}".format(self.context),
                    self._format_diff_review_content(errors),
                    syntax="Packages/Diff/Diff.sublime-syntax",
                )
                self.cleanup()
                return

            if self.mode == self.MODE_DRY_RUN:
                self._show_output_tab(
                    "Kubeapply Dry-Run @ {}".format(self.context),
                    self._format_report(errors),
                )
                self.cleanup()
                return

            # APPLY mode
            if errors and self.settings["dry_run_before_apply"]:
                self._abort_with_report(
                    errors,
                    "Kubeapply: dry-run / pre-checks failed — see report tab",
                )
                return

            self._confirm_and_apply()

        sublime.set_timeout(done, 0)

    def _build_apply_args(self, dry_run=False):
        # Namespace is written into the temp manifest when prompted — do not
        # pass -n here (avoids overriding other docs' namespaces).
        args = ["apply", "-f", self.manifest_path]
        if self.settings["validate"]:
            args.append("--validate=true")
        if dry_run:
            args.append("--dry-run=server")
        if self.settings["server_side_apply"]:
            args.append("--server-side")
            args.extend(["--field-manager", self.settings["field_manager"]])
        # Hard safety: never pass --force from this plugin
        _ = self.settings["allow_force"]
        return args

    def _format_report(self, errors):
        lines = []
        lines.append("Context: {}".format(self.context))
        if self.chosen_namespace:
            lines.append(
                "Namespace override (prompted): {}".format(self.chosen_namespace)
            )
        if self.created_namespaces:
            lines.append(
                "Namespaces created: {}".format(", ".join(self.created_namespaces))
            )
        lines.append("Mode: {}".format(self.mode))
        lines.append("")
        lines.append("Resources:")
        for item in self.exists_summary:
            state = (
                "EXISTS (will UPDATE / overwrite fields)"
                if item["exists"] is True
                else (
                    "NEW (will CREATE)"
                    if item["exists"] is False
                    else "UNKNOWN ({})".format(item.get("error") or "check failed")
                )
            )
            lines.append("  - {}  →  {}".format(item["label"], state))
        if self.dry_run_text:
            lines.append("")
            lines.append("=== dry-run=server ===")
            lines.append(self.dry_run_text)
        if self.diff_text:
            lines.append("")
            lines.append("=== kubectl diff ===")
            lines.append(self.diff_text)
        if errors:
            lines.append("")
            lines.append("=== errors ===")
            for err in errors:
                lines.append(err)
        return "\n".join(lines) + "\n"

    def _format_diff_review_content(self, errors=None):
        """
        Build a tab body that Diff.sublime-syntax can colorize.

        Keep metadata as plain lines (no leading +/-), then emit the raw
        kubectl unified diff so + is green and - is red.
        """
        lines = []
        lines.append("Kubeapply — review kubectl diff before apply")
        lines.append("Context: {}".format(self.context))
        if self.chosen_namespace:
            lines.append(
                "Namespace override (prompted): {}".format(self.chosen_namespace)
            )
        if self.created_namespaces:
            lines.append(
                "Namespaces created: {}".format(", ".join(self.created_namespaces))
            )
        lines.append("Mode: {}".format(self.mode))
        lines.append("")
        lines.append("Resources:")
        for item in self.exists_summary:
            if item["exists"] is True:
                mark = "~"
                state = "EXISTS (will UPDATE)"
            elif item["exists"] is False:
                mark = "*"
                state = "NEW (will CREATE)"
            else:
                mark = "?"
                state = "UNKNOWN ({})".format(item.get("error") or "check failed")
            # Avoid a leading "-" so Diff syntax does not paint summary red.
            lines.append("  {} {}  →  {}".format(mark, item["label"], state))

        if self.dry_run_text:
            lines.append("")
            lines.append("dry-run=server:")
            for dry_line in (self.dry_run_text or "").splitlines():
                # Prefix so Diff does not treat dry-run names as deletions.
                if dry_line.startswith("+") or dry_line.startswith("-"):
                    lines.append("  {}".format(dry_line))
                else:
                    lines.append(dry_line)

        if errors:
            lines.append("")
            lines.append("errors:")
            for err in errors:
                lines.append("  {}".format(err))

        lines.append("")
        lines.append("=" * 72)
        lines.append("kubectl diff (unified) — + added / - removed")
        lines.append("=" * 72)
        lines.append("")
        if self.diff_text:
            lines.append(self.diff_text.rstrip("\n"))
        else:
            lines.append("(no diff output)")
        lines.append("")
        return "\n".join(lines)

    def _show_output_tab(self, title, content, focus=True, syntax=None):
        if not self.settings["show_result_in_tab"]:
            # Avoid native message_dialog (macOS ST4 sheet crashes). Use a tab anyway.
            pass
        new_view = self.window.new_file()
        new_view.set_name(title)
        new_view.set_scratch(True)
        new_view.set_read_only(False)
        # Insert command sets read_only when done (avoid racing set_read_only).
        new_view.run_command("kubeapply_insert_content", {"content": content})
        if syntax:
            self._assign_syntax(new_view, syntax)
        if focus:
            self.window.focus_view(new_view)
        return new_view

    def _assign_syntax(self, view, syntax):
        """Prefer ST4 assign_syntax; fall back to set_syntax_file."""
        try:
            view.assign_syntax(syntax)
        except Exception:
            try:
                view.set_syntax_file(syntax)
            except Exception:
                pass

    def _confirm_and_apply(self):
        updates = [i for i in self.exists_summary if i["exists"] is True]
        creates = [i for i in self.exists_summary if i["exists"] is False]
        unknowns = [i for i in self.exists_summary if i["exists"] is None]

        # Show kubectl diff in a tab BEFORE any apply confirmation so the user
        # can review changes prior to overwriting existing kinds.
        show_diff = self.settings["show_diff_before_apply"] and bool(self.diff_text)
        must_review_diff = show_diff and bool(updates)
        if show_diff:
            title = (
                "Kubeapply DIFF — review before apply @ {}".format(self.context)
                if updates
                else "Kubeapply Pre-Apply Report @ {}".format(self.context)
            )
            self._show_output_tab(
                title,
                self._format_diff_review_content([]),
                focus=True,
                syntax="Packages/Diff/Diff.sublime-syntax",
            )
            sublime.status_message(
                "Kubeapply: review DIFF tab, then confirm in the quick panel"
            )

        summary_lines = [
            "Apply to context: {}".format(self.context),
        ]
        if self.created_namespaces:
            summary_lines.append(
                "Namespaces created: {}".format(", ".join(self.created_namespaces))
            )
        if self.chosen_namespace:
            summary_lines.append(
                "Namespace (prompted): {}".format(self.chosen_namespace)
            )
        if creates:
            summary_lines.append("CREATE ({})".format(len(creates)))
            for i in creates[:6]:
                summary_lines.append("  + {}".format(i["label"]))
            if len(creates) > 6:
                summary_lines.append("  … {} more".format(len(creates) - 6))
        if updates:
            summary_lines.append("UPDATE existing ({})".format(len(updates)))
            for i in updates[:6]:
                summary_lines.append("  ~ {}".format(i["label"]))
            if len(updates) > 6:
                summary_lines.append("  … {} more".format(len(updates) - 6))
        if unknowns:
            summary_lines.append(
                "Could not verify existence ({})".format(len(unknowns))
            )
            for i in unknowns[:4]:
                summary_lines.append("  ? {}".format(i["label"]))
        if updates:
            summary_lines.append(
                "WARNING: existing live objects will be patched/overwritten."
            )
        if must_review_diff:
            summary_lines.append(
                "Diff is open in tab — review it before confirming."
            )

        detail = " | ".join(
            line for line in summary_lines if not line.startswith("  ")
        )
        # Keep quick_panel subtitle readable
        if len(detail) > 200:
            detail = detail[:197] + "…"

        if must_review_diff:
            ok_label = "Reviewed diff — apply UPDATE ({} resource(s))".format(
                len(updates)
            )
            if creates:
                ok_label = (
                    "Reviewed diff — apply ({} update / {} create)".format(
                        len(updates), len(creates)
                    )
                )
        elif updates and creates:
            ok_label = "Apply ({} update / {} create)".format(
                len(updates), len(creates)
            )
        elif updates:
            ok_label = "Update {} resource(s)".format(len(updates))
        elif creates:
            ok_label = "Create {} resource(s)".format(len(creates))
        else:
            ok_label = "Create"

        def after_first_confirm():
            if updates:
                names = ", ".join(i["label"] for i in updates[:6])
                if len(updates) > 6:
                    names += ", …"
                self._confirm_quick(
                    "Overwrite on '{}' — final confirm".format(self.context),
                    names
                    + (
                        " | Diff tab already shown — proceed only if OK"
                        if must_review_diff
                        else ""
                    ),
                    self._start_apply_after_confirm,
                )
                return
            self._start_apply_after_confirm()

        if self.settings["require_confirmation"] or must_review_diff:
            # Slightly longer delay when a diff tab was just opened so ST can
            # focus it before the quick panel appears on top.
            delay_ms = 80 if show_diff else 10

            def show_confirm():
                self._confirm_quick(ok_label, detail, after_first_confirm)

            sublime.set_timeout(show_confirm, delay_ms)
            return

        self._start_apply_after_confirm()

    def _start_apply_after_confirm(self):
        sublime.status_message("Kubeapply: applying...")
        threading.Thread(target=self._apply_async).start()

    def _apply_async(self):
        args = self._build_apply_args(dry_run=False)
        code, out, err = self._kubectl(self._with_context(args))

        def done():
            report = self._format_report([])
            report += "\n=== kubectl apply ===\n"
            report += (out or "") + (("\n" + err) if err else "")
            report += "\nexit code: {}\n".format(code)
            title = (
                "Kubeapply Applied @ {}".format(self.context)
                if code == 0
                else "Kubeapply Apply FAILED @ {}".format(self.context)
            )
            self._show_output_tab(title, report)
            if code == 0:
                sublime.status_message("Kubeapply: apply succeeded")
            else:
                # Report tab already open — do not show error_message after new_file.
                sublime.status_message(
                    "Kubeapply: apply failed (exit {}) — see report tab".format(code)
                )
            self.cleanup()

        sublime.set_timeout(done, 0)


class KubeapplyOpenFileCommand(sublime_plugin.WindowCommand):
    """Command Palette: Kubeapply: Apply Open File"""

    def run(self):
        view = self.window.active_view()
        _KubeapplyFlow(self.window, view, _KubeapplyFlow.MODE_APPLY).start()


class KubeapplyDryRunOpenFileCommand(sublime_plugin.WindowCommand):
    """Command Palette: Kubeapply: Dry-Run Open File"""

    def run(self):
        view = self.window.active_view()
        _KubeapplyFlow(self.window, view, _KubeapplyFlow.MODE_DRY_RUN).start()


class KubeapplyDiffOpenFileCommand(sublime_plugin.WindowCommand):
    """Command Palette: Kubeapply: Diff Open File"""

    def run(self):
        view = self.window.active_view()
        _KubeapplyFlow(self.window, view, _KubeapplyFlow.MODE_DIFF).start()


class KubeapplyInsertContentCommand(sublime_plugin.TextCommand):
    def run(self, edit, content):
        self.view.insert(edit, 0, content)
        self.view.set_read_only(True)


class KubeapplyOpenSettingsCommand(sublime_plugin.ApplicationCommand):
    def run(self):
        sublime.run_command(
            "open_file", {"file": "${packages}/User/Kubeapply.sublime-settings"}
        )

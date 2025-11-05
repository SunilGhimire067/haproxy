"""
Entrypoint: Streamlit web UI (default) and optional desktop GUI (--desktop).
PyQt5 is imported lazily only when desktop mode is requested to avoid import errors
when running the web UI.
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple
import os
import hashlib
from datetime import datetime
import json

HERE = Path(__file__).resolve().parent
DEFAULT_CFG = (HERE.parent / "examples" / "haproxy.cfg").resolve()


def read_config(path: Path) -> List[str]:
    path = Path(path)
    return path.read_text(encoding="utf-8").splitlines()


def find_backends(lines: List[str]) -> List[Tuple[str, int, int]]:
    backends = []
    cur_name = None
    cur_start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if not parts:
            continue
        if parts[0] in ("backend", "listen", "frontend"):
            if cur_name is not None:
                backends.append((cur_name, cur_start, i))
            if parts[0] == "backend":
                cur_name = parts[1] if len(parts) > 1 else "<unnamed>"
                cur_start = i
            else:
                cur_name = None
                cur_start = None
    if cur_name is not None:
        backends.append((cur_name, cur_start, len(lines)))
    return backends


def get_backend_text(lines: List[str], backend_tuple: Tuple[str, int, int]) -> str:
    _, s, e = backend_tuple
    return "\n".join(lines[s:e])


def replace_backend(lines: List[str], backend_tuple: Tuple[str, int, int], new_text: str) -> List[str]:
    name, s, e = backend_tuple
    new_lines = new_text.splitlines()
    return lines[:s] + new_lines + lines[e:]


def backup_file(path: Path) -> Path:
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # create backup in same directory with timestamp before .bak
    bak = path.with_name(f"{path.name}.{ts}.bak")
    bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return bak



def write_config(path: Path, lines: List[str]):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def try_restart_haproxy() -> Tuple[int, str]:
    cmds = [
        ["brew", "services", "restart", "haproxy"],
        ["sudo", "brew", "services", "restart", "haproxy"],
        ["sudo", "systemctl", "reload", "haproxy"],
        ["sudo", "systemctl", "restart", "haproxy"],
        ["service", "haproxy", "reload"],
        ["sudo", "service", "haproxy", "reload"],
    ]
    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            out = f"Cmd: {' '.join(cmd)}\nReturn: {proc.returncode}\nStdout:\n{proc.stdout}\nStderr:\n{proc.stderr}"
            if proc.returncode == 0:
                return proc.returncode, out
        except FileNotFoundError:
            continue
    return 127, "No suitable restart command found on this system."


def _get_stored_credentials():
    """
    Return tuple: (admin_user, admin_password_spec, read_user, read_password_spec)
    Environment variables:
      - HAPROXY_UI_USER / HAPROXY_UI_PASSWORD      -> admin (legacy)
      - HAPROXY_UI_READ_USER / HAPROXY_UI_READ_PASSWORD -> read-only user
    Password spec may be plain or "sha256:<hex>"
    """
    admin_user = os.getenv("HAPROXY_UI_USER")
    admin_pwd = os.getenv("HAPROXY_UI_PASSWORD")
    read_user = os.getenv("HAPROXY_UI_READ_USER")
    read_pwd = os.getenv("HAPROXY_UI_READ_PASSWORD")
    return admin_user, admin_pwd, read_user, read_pwd


def _check_password(plain_password: str, stored_spec: str | None) -> bool:
    if stored_spec is None:
        return True
    if stored_spec.startswith("sha256:"):
        expected = stored_spec.split(":", 1)[1]
        return hashlib.sha256(plain_password.encode()).hexdigest() == expected
    return plain_password == stored_spec


def _authenticate(username: str, password: str) -> str | None:
    """
    Return role string ('admin' or 'read') if credentials match, otherwise None.
    """
    admin_user, admin_pwd, read_user, read_pwd = _get_stored_credentials()

    # If no admin configured, auth is disabled -> treat as admin
    if not admin_user and not read_user:
        return "admin"

    # Check admin
    if admin_user and username == admin_user and _check_password(password, admin_pwd):
        return "admin"

    # Check read-only
    if read_user and username == read_user and _check_password(password, read_pwd):
        return "read"

    return None


def _require_login(st) -> bool:
    """
    Return True when the user is authenticated (or auth is disabled).
    Stores role in st.session_state['haproxy_ui_role'].
    """
    admin_user, admin_pwd, read_user, read_pwd = _get_stored_credentials()
    # no configured users -> no auth
    if not admin_user and not read_user:
        st.session_state.setdefault("haproxy_ui_role", "admin")
        return True

    if "haproxy_ui_auth" not in st.session_state:
        st.session_state.haproxy_ui_auth = False
        st.session_state.haproxy_ui_role = None
        st.session_state.haproxy_ui_user = None

    # already authenticated
    if st.session_state.haproxy_ui_auth:
        if st.sidebar.button("Logout"):
            st.session_state.haproxy_ui_auth = False
            st.session_state.haproxy_ui_role = None
            st.session_state.haproxy_ui_user = None
            st.experimental_rerun()
        st.sidebar.markdown(f"Logged in as **{st.session_state.haproxy_ui_user}** ({st.session_state.haproxy_ui_role})")
        return True

    # show login form
    st.sidebar.markdown("### Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        role = _authenticate(username, password)
        if role:
            st.session_state.haproxy_ui_auth = True
            st.session_state.haproxy_ui_role = role
            st.session_state.haproxy_ui_user = username
            st.experimental_rerun()
        else:
            st.sidebar.error("Invalid username or password")

    return False


def make_streamlit_ui(config_path: Path):
    try:
        import streamlit as st
    except Exception:
        print("Streamlit is required for web UI. Install with: python3 -m pip install streamlit", file=sys.stderr)
        raise

    # Require login first
    if not _require_login(st):
        st.title("HAProxy Backends Editor")
        st.info("Please login using the form in the sidebar.")
        return

    # get role for UI controls
    role = st.session_state.get("haproxy_ui_role", "admin")

    st.set_page_config(page_title="HAProxy Backends Editor", layout="wide")
    st.title("HAProxy Backends Editor")

    if role == "read":
        st.warning("You are logged in with read-only access. Editing, saving and restarting are disabled.")

    cfg_path = st.sidebar.text_input("Haproxy config path", str(config_path))
    cfg = Path(cfg_path)
    if not cfg.exists():
        st.sidebar.error(f"Config file not found: {cfg}")
        return

    lines = read_config(cfg)
    backends = find_backends(lines)
    if not backends:
        st.warning("No 'backend' sections found in configuration.")
        st.code("\n".join(lines[:200]))
        return

    names = [b[0] for b in backends]
    sel = st.selectbox("Select backend", names, index=0)

    selected_tuple = next(b for b in backends if b[0] == sel)
    backend_text = get_backend_text(lines, selected_tuple)

    st.subheader(f"Editing backend: {sel}")
    # disable editing for read-only users
    edited = st.text_area("Backend contents", value=backend_text, height=300, key=f"backend_{sel}", disabled=(role != "admin"))

    col1, col2 = st.columns(2)
    with col1:
        # Save button disabled for read-only role
        if st.button("Save changes", disabled=(role != "admin")):
            if role != "admin":
                st.error("You do not have permission to save changes.")
            else:
                try:
                    old_text = backend_text
                    new_text = edited
                    
                    if old_text != new_text:
                        backup = backup_file(cfg)
                        new_lines = replace_backend(lines, selected_tuple, new_text)
                        write_config(cfg, new_lines)
                        
                        # Log the change
                        username = st.session_state.get('haproxy_ui_user', 'unknown')
                        log_change(cfg, sel, old_text, new_text, username)
                        
                        st.success(f"Saved and logged. Backup written to {backup}")
                except Exception as exc:
                    st.error(f"Failed to save: {exc}")

    with col2:
        # Restart button disabled for read-only role
        if st.button("Restart HAProxy", disabled=(role != "admin")):
            if role != "admin":
                st.error("You do not have permission to restart HAProxy.")
            else:
                code, out = try_restart_haproxy()
                if code == 0:
                    st.success("Restart/reload command succeeded.")
                else:
                    st.error(f"Restart command failed (code {code}). See output below.")
                st.code(out)

    st.markdown("---")
    st.caption(f"Config path: {cfg} — {len(backends)} backend(s) found.")
    if st.checkbox("Show raw config (first 400 lines)"):
        st.code("\n".join(read_config(cfg)[:400]))


def launch_desktop_editor(config_path: Path):
    try:
        import importlib
        QtWidgets = importlib.import_module("PyQt5.QtWidgets")
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "PyQt5 is required for desktop mode. Install it with:\n"
            "python3 -m pip install PyQt5\n\n"
            "Or run the web UI with Streamlit:\n"
            "python3 -m pip install streamlit\n"
            "streamlit run src/main.py"
        ) from e

    QApplication = QtWidgets.QApplication
    QMainWindow = QtWidgets.QMainWindow
    QWidget = QtWidgets.QWidget
    QVBoxLayout = QtWidgets.QVBoxLayout
    QHBoxLayout = QtWidgets.QHBoxLayout
    QPushButton = QtWidgets.QPushButton
    QListWidget = QtWidgets.QListWidget
    QTextEdit = QtWidgets.QTextEdit
    QMessageBox = QtWidgets.QMessageBox
    QFileDialog = QtWidgets.QFileDialog

    class EditorWindow(QMainWindow):
        def __init__(self, cfg: Path):
            super().__init__()
            self.cfg = cfg
            self.setWindowTitle("HAProxy Backends Editor - Desktop")
            self.resize(900, 600)
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QHBoxLayout()
            central.setLayout(main_layout)

            left = QVBoxLayout()
            self.listw = QListWidget()
            left.addWidget(self.listw)

            btn_reload = QPushButton("Reload file")
            btn_reload.clicked.connect(self.load_config)
            left.addWidget(btn_reload)

            main_layout.addLayout(left, 1)

            right = QVBoxLayout()
            self.text = QTextEdit()
            right.addWidget(self.text, 1)

            hb = QHBoxLayout()
            btn_save = QPushButton("Save backend")
            btn_save.clicked.connect(self.save_backend)
            btn_restart = QPushButton("Restart HAProxy")
            btn_restart.clicked.connect(self.restart_haproxy_action)
            btn_open = QPushButton("Open config...")
            btn_open.clicked.connect(self.open_config_dialog)
            hb.addWidget(btn_save)
            hb.addWidget(btn_restart)
            hb.addWidget(btn_open)
            right.addLayout(hb)

            main_layout.addLayout(right, 3)

            self.backends = []
            self.load_config()
            self.listw.currentRowChanged.connect(self.on_select)

        def open_config_dialog(self):
            p, _ = QFileDialog.getOpenFileName(self, "Open haproxy config", str(self.cfg))
            if p:
                self.cfg = Path(p)
                self.load_config()

        def load_config(self):
            try:
                lines = read_config(self.cfg)
                self.backends = find_backends(lines)
                self.listw.clear()
                for b in self.backends:
                    self.listw.addItem(b[0])
                if self.backends:
                    self.listw.setCurrentRow(0)
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to read config: {exc}")

        def on_select(self, idx):
            if idx < 0 or idx >= len(self.backends):
                self.text.clear()
                return
            lines = read_config(self.cfg)
            txt = get_backend_text(lines, self.backends[idx])
            self.text.setPlainText(txt)

        def save_backend(self):
            idx = self.listw.currentRow()
            if idx < 0:
                QMessageBox.warning(self, "No selection", "Select a backend first.")
                return
            try:
                lines = read_config(self.cfg)
                backend_name = self.backends[idx][0]
                old_text = get_backend_text(lines, self.backends[idx])
                new_text = self.text.toPlainText()
                
                # Only save if there are actual changes
                if old_text != new_text:
                    new_lines = replace_backend(lines, self.backends[idx], new_text)
                    write_config(self.cfg, new_lines)
                    
                    # Log the change
                    username = os.getenv('USER', 'unknown')  # For desktop UI
                    log_change(self.cfg, backend_name, old_text, new_text, username)
                    
                    QMessageBox.information(self, "Saved", "Backend saved and change logged.")
                    self.load_config()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to save: {exc}")

        def restart_haproxy_action(self):
            code, out = try_restart_haproxy()
            if code == 0:
                QMessageBox.information(self, "Restart", "Restart/reload succeeded.")
            else:
                QMessageBox.warning(self, "Restart", f"Restart may have failed (code {code}).\nSee terminal for details.")
            print(out)

    app = QApplication(sys.argv)
    win = EditorWindow(config_path)
    win.show()
    sys.exit(app.exec_())


def log_change(config_path: Path, backend_name: str, old_text: str, new_text: str, username: str):
    """Log configuration changes to an audit file next to the config."""
    log_path = config_path.with_suffix('.audit.jsonl')
    entry = {
        "timestamp": datetime.now().isoformat(),
        "user": username,
        "backend": backend_name,
        "config_file": str(config_path),
        "old_config": old_text,
        "new_config": new_text
    }
    
    # Append the log entry
    with log_path.open('a') as f:
        json.dump(entry, f)
        f.write('\n')


def main():
    parser = argparse.ArgumentParser(description="HAProxy backends editor (web + desktop).")
    parser.add_argument("--desktop", action="store_true", help="Launch desktop GUI (requires PyQt5).")
    parser.add_argument("--config", "-c", default=str(DEFAULT_CFG), help="Path to haproxy config file.")
    args = parser.parse_args()

    cfg = Path(args.config)
    if args.desktop:
        # Launch desktop editor (will raise a friendly error if PyQt5 missing)
        launch_desktop_editor(cfg)
    else:
        try:
            make_streamlit_ui(cfg)
        except Exception as e:
            msg = (
                "Failed to launch Streamlit web UI (is streamlit installed?).\n"
                "To run web UI, install streamlit and run:\n\n"
                "  python3 -m pip install streamlit\n"
                "  streamlit run src/main.py\n\n"
                "Or run desktop mode (requires PyQt5):\n\n"
                "  python3 -m pip install PyQt5\n"
                "  python3 src/main.py --desktop\n\n"
                f"Error: {e}"
            )
            print(msg, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
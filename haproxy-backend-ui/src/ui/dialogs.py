from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox


class EditBackendDialog(QDialog):
    def __init__(self, backend_name, backend_settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Backend")
        self.backend_name = backend_name
        self.backend_settings = backend_settings
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel(f"Editing backend: {self.backend_name}")
        layout.addWidget(self.label)

        self.settings_input = QLineEdit(self.backend_settings)
        layout.addWidget(self.settings_input)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_changes)
        layout.addWidget(self.save_button)

        self.setLayout(layout)

    def save_changes(self):
        new_settings = self.settings_input.text()
        # Logic to save the new settings goes here
        QMessageBox.information(self, "Success", "Backend settings saved successfully.")
        self.accept()


class ConfirmRestartDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm Restart")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Are you sure you want to restart the HAProxy service?")
        layout.addWidget(self.label)

        self.confirm_button = QPushButton("Restart")
        self.confirm_button.clicked.connect(self.restart_haproxy)
        layout.addWidget(self.confirm_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

    def restart_haproxy(self):
        # Logic to restart HAProxy goes here
        QMessageBox.information(self, "Restart", "HAProxy service restarted successfully.")
        self.accept()
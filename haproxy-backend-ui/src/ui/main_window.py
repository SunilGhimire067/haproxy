from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QPushButton, QListWidget, QMessageBox, QInputDialog
from core.manager import Manager
from core.parser import Parser

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HAProxy Backend Manager")
        self.setGeometry(100, 100, 600, 400)

        self.manager = Manager()
        self.parser = Parser()
        self.backends = self.manager.get_backends()

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        self.backend_list = QListWidget()
        self.backend_list.addItems(self.backends)
        layout.addWidget(self.backend_list)

        edit_button = QPushButton("Edit Backend")
        edit_button.clicked.connect(self.edit_backend)
        layout.addWidget(edit_button)

        restart_button = QPushButton("Restart Backend")
        restart_button.clicked.connect(self.restart_backend)
        layout.addWidget(restart_button)

        central_widget.setLayout(layout)

    def edit_backend(self):
        selected_backend = self.backend_list.currentItem()
        if selected_backend:
            backend_name = selected_backend.text()
            new_name, ok = QInputDialog.getText(self, "Edit Backend", "New name:", text=backend_name)
            if ok and new_name:
                self.manager.edit_backend(backend_name, new_name)
                self.backend_list.clear()
                self.backend_list.addItems(self.manager.get_backends())
        else:
            QMessageBox.warning(self, "Warning", "Please select a backend to edit.")

    def restart_backend(self):
        selected_backend = self.backend_list.currentItem()
        if selected_backend:
            backend_name = selected_backend.text()
            if self.manager.restart_backend(backend_name):
                QMessageBox.information(self, "Success", f"Backend '{backend_name}' restarted successfully.")
            else:
                QMessageBox.warning(self, "Error", f"Failed to restart backend '{backend_name}'.")
        else:
            QMessageBox.warning(self, "Warning", "Please select a backend to restart.")
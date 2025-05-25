# main.py
# Student Name: Xingzuo Li
# Student Number: 2295275
# GitHub Username: yourGitHubUsername

import sys
import json
import base64
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QListWidget, QPushButton, QVBoxLayout,
    QHBoxLayout, QWidget, QMessageBox, QListWidgetItem, QDialog, QFormLayout,
    QLineEdit, QDialogButtonBox, QLabel, QSlider, QCheckBox
)
from PyQt6.QtCore import Qt
from genpass import generate_password

def encrypt(data: str) -> bytes:
    return base64.b64encode(data.encode())

def decrypt(data: bytes) -> str:
    return base64.b64decode(data).decode()

class PasswordGeneratorDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Generator")
        self.setFixedSize(400, 300)

        layout = QVBoxLayout()

        self.length_label = QLabel("Password Length: 12")
        layout.addWidget(self.length_label)

        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(12)
        self.length_slider.valueChanged.connect(self.update_length_label)
        layout.addWidget(self.length_slider)

        self.lowercase_checkbox = QCheckBox("Include Lowercase")
        self.lowercase_checkbox.setChecked(True)
        layout.addWidget(self.lowercase_checkbox)

        self.uppercase_checkbox = QCheckBox("Include Uppercase")
        self.uppercase_checkbox.setChecked(True)
        layout.addWidget(self.uppercase_checkbox)

        self.digits_checkbox = QCheckBox("Include Digits")
        self.digits_checkbox.setChecked(True)
        layout.addWidget(self.digits_checkbox)

        self.symbols_checkbox = QCheckBox("Include Symbols")
        self.symbols_checkbox.setChecked(True)
        layout.addWidget(self.symbols_checkbox)

        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

        generate_button = QPushButton("Generate")
        generate_button.clicked.connect(self.generate)
        layout.addWidget(generate_button)

        use_button = QPushButton("Use This Password")
        use_button.clicked.connect(self.accept)
        layout.addWidget(use_button)

        self.setLayout(layout)
        self.generated_password = ""

    def update_length_label(self, value):
        self.length_label.setText(f"Password Length: {value}")

    def generate(self):
        length = self.length_slider.value()
        lower = self.lowercase_checkbox.isChecked()
        upper = self.uppercase_checkbox.isChecked()
        digits = self.digits_checkbox.isChecked()
        symbols = self.symbols_checkbox.isChecked()

        if not (lower or upper or digits or symbols):
            QMessageBox.warning(self, "Warning", "At least one character type must be selected.")
            return

        self.generated_password = generate_password(length, lower, upper, digits, symbols)
        self.result_label.setText(self.generated_password)

    def get_password(self):
        return self.generated_password

class EntryDialog(QDialog):
    def __init__(self, email="", password=""):
        super().__init__()
        self.setWindowTitle("Entry")
        self.setFixedSize(300, 200)

        layout = QFormLayout()

        self.email_input = QLineEdit()
        self.email_input.setText(email)
        layout.addRow("Email:", self.email_input)

        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setText(password)
        password_layout.addWidget(self.password_input)

        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.open_generator)
        password_layout.addWidget(self.generate_button)

        layout.addRow("Password:", password_layout)

        buttons = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        self.button_box = QDialogButtonBox(buttons)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addRow(self.button_box)

        self.setLayout(layout)

    def open_generator(self):
        dialog = PasswordGeneratorDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            generated = dialog.get_password()
            if generated:
                self.password_input.setText(generated)

    def get_data(self):
        return self.email_input.text().strip(), self.password_input.text().strip()

class PasswordVaultApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Vault")
        self.setGeometry(100, 100, 600, 400)

        main_layout = QHBoxLayout()

        self.credential_list = QListWidget()
        main_layout.addWidget(self.credential_list)

        button_layout = QVBoxLayout()

        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.add_entry)
        button_layout.addWidget(self.add_button)

        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.edit_entry)
        button_layout.addWidget(self.edit_button)

        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_entry)
        button_layout.addWidget(self.delete_button)

        button_layout.addStretch()
        main_layout.addLayout(button_layout)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.credentials = []
        self.load_vault()

    def add_entry(self):
        dialog = EntryDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            email, password = dialog.get_data()
            if not email or not password:
                QMessageBox.warning(self, "Warning", "Both email and password are required.")
                return
            self.credentials.append({'email': email, 'password': password})
            self.refresh_list()

    def edit_entry(self):
        selected = self.credential_list.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "Warning", "Please select an entry to edit.")
            return
        entry = self.credentials[selected]
        dialog = EntryDialog(entry['email'], entry['password'])
        if dialog.exec() == QDialog.DialogCode.Accepted:
            email, password = dialog.get_data()
            if not email or not password:
                QMessageBox.warning(self, "Warning", "Both email and password are required.")
                return
            self.credentials[selected] = {'email': email, 'password': password}
            self.refresh_list()

    def delete_entry(self):
        selected = self.credential_list.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "Warning", "Please select an entry to delete.")
            return
        reply = QMessageBox.question(self, "Delete Entry", "Are you sure you want to delete this entry?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            del self.credentials[selected]
            self.refresh_list()

    def load_vault(self):
        self.credentials.clear()
        if not os.path.exists("vault.enc"):
            return
        try:
            with open("vault.enc", "rb") as file:
                encrypted_data = file.read()
                decrypted_data = decrypt(encrypted_data)
                self.credentials = json.loads(decrypted_data)
                self.refresh_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load vault: {str(e)}")

    def save_vault(self):
        try:
            data = json.dumps(self.credentials)
            encrypted_data = encrypt(data)
            with open("vault.enc", "wb") as file:
                file.write(encrypted_data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save vault: {str(e)}")

    def refresh_list(self):
        self.credential_list.clear()
        for entry in sorted(self.credentials, key=lambda x: x['email'].lower()):
            masked = '*' * len(entry['password'])
            item = QListWidgetItem(f"{entry['email']} | {masked}")
            self.credential_list.addItem(item)

    def closeEvent(self, event):
        self.save_vault()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordVaultApp()
    window.show()
    sys.exit(app.exec())

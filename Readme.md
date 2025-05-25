# Secure Password Vault (with Password Generator)

This is a simple password manager app built using PyQt6. It lets you save email and password pairs in a small vault. Your passwords are encrypted and saved in a file called `vault.enc`. You can add, edit, or delete entries easily. There’s also a password generator if you need help creating strong passwords.

## Features

- Add new email/password entries
- Edit existing entries
- Delete entries with confirmation
- See a list of emails (passwords are hidden by default)
- Built-in password generator with length slider and options for character types (lowercase, uppercase, digits, symbols)
- Data is saved automatically to `vault.enc` when you close the app, and loaded again when you open it


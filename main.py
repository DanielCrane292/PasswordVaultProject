# main.py
# Student Name: Xingzuo Li
# Student Number: 2295275
# GitHub Username: DanielCrane292
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout,
    QWidget, QDialog, QLabel, QHBoxLayout, QMenuBar, QMenu,
    QLineEdit, QComboBox
)

from PyQt6.QtGui import QAction


# Dialog for Unit Converter
class UnitConverterDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unit Converter")

        # Input label and field
        self.input_label = QLabel("Enter value:")
        self.input_field = QLineEdit()

        # From unit
        self.from_label = QLabel("From:")
        self.from_combo = QComboBox()
        self.from_combo.addItems(["Meters", "Feet", "Celsius", "Fahrenheit"])

        # To unit
        self.to_label = QLabel("To:")
        self.to_combo = QComboBox()
        self.to_combo.addItems(["Meters", "Feet", "Celsius", "Fahrenheit"])

        # Convert button
        self.convert_button = QPushButton("Convert")
        self.convert_button.clicked.connect(self.convert_units)

        # Result display
        self.result_label = QLabel("Result: ")
        self.result_value = QLabel("")

        # Layouts
        layout = QVBoxLayout()
        layout.addWidget(self.input_label)
        layout.addWidget(self.input_field)

        layout.addWidget(self.from_label)
        layout.addWidget(self.from_combo)

        layout.addWidget(self.to_label)
        layout.addWidget(self.to_combo)

        layout.addWidget(self.convert_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_value)

        self.setLayout(layout)

    def convert_units(self):
        try:
            value = float(self.input_field.text())
            from_unit = self.from_combo.currentText()
            to_unit = self.to_combo.currentText()

            # Conversion logic
            if from_unit == to_unit:
                result = value
            elif from_unit == "Meters" and to_unit == "Feet":
                result = value * 3.28084
            elif from_unit == "Feet" and to_unit == "Meters":
                result = value / 3.28084
            elif from_unit == "Celsius" and to_unit == "Fahrenheit":
                result = (value * 9/5) + 32
            elif from_unit == "Fahrenheit" and to_unit == "Celsius":
                result = (value - 32) * 5/9
            else:
                result = "Invalid conversion"

            self.result_value.setText(f"{result}")
        except ValueError:
            self.result_value.setText("Invalid input")


# Dialog for Calculator
from PyQt6.QtWidgets import (
    QDialog, QLabel, QVBoxLayout, QLineEdit, QComboBox, QPushButton
)

class CalculatorDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Calculator")

        # Input fields
        self.num1_label = QLabel("Number 1:")
        self.num1_input = QLineEdit()

        self.num2_label = QLabel("Number 2:")
        self.num2_input = QLineEdit()

        # Operator selection
        self.operator_label = QLabel("Operator:")
        self.operator_combo = QComboBox()
        self.operator_combo.addItems(["+", "-", "*", "/"])

        # Calculate button
        self.calc_button = QPushButton("Calculate")
        self.calc_button.clicked.connect(self.calculate_result)

        # Result display
        self.result_label = QLabel("Result: ")
        self.result_value = QLabel("")

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.num1_label)
        layout.addWidget(self.num1_input)
        layout.addWidget(self.num2_label)
        layout.addWidget(self.num2_input)
        layout.addWidget(self.operator_label)
        layout.addWidget(self.operator_combo)
        layout.addWidget(self.calc_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_value)

        self.setLayout(layout)

    def calculate_result(self):
        try:
            num1 = float(self.num1_input.text())
            num2 = float(self.num2_input.text())
            operator = self.operator_combo.currentText()

            if operator == "+":
                result = num1 + num2
            elif operator == "-":
                result = num1 - num2
            elif operator == "*":
                result = num1 * num2
            elif operator == "/":
                if num2 == 0:
                    self.result_value.setText("Cannot divide by zero")
                    return
                result = num1 / num2
            else:
                result = "Invalid operator"

            self.result_value.setText(str(result))

        except ValueError:
            self.result_value.setText("Invalid input")



# Main Application Window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Utility App - Unit Converter & Calculator")

        # Create menu bar
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("File")
        tools_menu = menu_bar.addMenu("Tools")
        help_menu = menu_bar.addMenu("Help")

        # Create actions
        open_converter_action = QAction("Open Unit Converter", self)
        open_converter_action.setShortcut("Ctrl+U")
        open_converter_action.triggered.connect(self.open_unit_converter)

        open_calculator_action = QAction("Open Calculator", self)
        open_calculator_action.setShortcut("Ctrl+C")
        open_calculator_action.triggered.connect(self.open_calculator)

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)

        # Add actions to menus
        tools_menu.addAction(open_converter_action)
        tools_menu.addAction(open_calculator_action)
        file_menu.addAction(exit_action)

        # Central widget with buttons
        central_widget = QWidget()
        layout = QVBoxLayout()

        btn_converter = QPushButton("Open Unit Converter")
        btn_converter.clicked.connect(self.open_unit_converter)

        btn_calculator = QPushButton("Open Calculator")
        btn_calculator.clicked.connect(self.open_calculator)

        layout.addWidget(btn_converter)
        layout.addWidget(btn_calculator)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def open_unit_converter(self):
        dialog = UnitConverterDialog()
        dialog.exec()

    def open_calculator(self):
        dialog = CalculatorDialog()
        dialog.exec()


# Entry point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

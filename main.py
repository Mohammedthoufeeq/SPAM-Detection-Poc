import re
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.api_key = ''

    def initUI(self):
        self.setWindowTitle('SMS Spam Detector')
        self.setFixedSize(400, 250)

        # Create widgets
        self.message_input = QLineEdit()
        self.result_label = QLabel()
        self.api_key_input = QLineEdit()
        self.api_key_label = QLabel('API Key:')
        self.check_button = QPushButton('Check')
        self.set_api_key_button = QPushButton('Set API Key')
        self.remove_api_key_button = QPushButton('Remove API Key')

        # Layouts
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        middle_layout = QVBoxLayout()
        bottom_layout = QHBoxLayout()

        # Add widgets to layouts
        top_layout.addWidget(self.api_key_label)
        top_layout.addWidget(self.api_key_input)
        top_layout.addWidget(self.set_api_key_button)
        top_layout.addWidget(self.remove_api_key_button)

        middle_layout.addWidget(QLabel('Enter message:'))
        middle_layout.addWidget(self.message_input)
        middle_layout.addWidget(self.result_label)

        bottom_layout.addWidget(self.check_button)

        # Add layouts to main layout
        main_layout.addLayout(top_layout)
        main_layout.addLayout(middle_layout)
        main_layout.addLayout(bottom_layout)

        # Set the main layout
        self.setLayout(main_layout)

        # Button connections
        self.check_button.clicked.connect(self.check_for_spam)
        self.set_api_key_button.clicked.connect(self.set_api_key)
        self.remove_api_key_button.clicked.connect(self.remove_api_key)

    def check_for_spam(self):
        message = self.message_input.text()

        # Check if message contains certain keywords
        keywords = ['credit card', 'free money', 'lottery', 'prize', 'win']
        if any(keyword in message.lower() for keyword in keywords):
            self.result_label.setText('SPAM DETECTED: Message contains one or more spam keywords.')
            return

        # Check if message contains a URL
        url_pattern = r'http?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        url_match = re.search(url_pattern, message)
        if url_match:
            url = url_match.group(0)

            # Check if API key is set
            if not self.api_key:
                QMessageBox.warning(self, 'API Key Error', 'API Key is not set. Please enter a valid API Key.')
                return

            # Check URL with VirusTotal
            params = {'apikey': self.api_key, 'resource': url}
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            json_response = response.json()

            if json_response['response_code'] == 1:
                if json_response['positives'] > 0:
                    self.result_label.setText('SPAM DETECTED: Message contains a malicious URL.')
                    return
                else:
                    self.result_label.setText('Message is not spam.')
                    return
            else:
                self.result_label.setText('Unable to check URL. Please try again later.')
                return

        self.result_label.setText('Message is not spam.')

    def set_api_key(self):
        api_key = self.api_key_input.text()
        if api_key:
            self.api_key = api_key
            QMessageBox.information(self, 'API Key Set', 'API Key has been set successfully.')
        else:
            QMessageBox.warning(self, 'API Key Error', 'Please enter a valid API Key.')

    def remove_api_key(self):
        self.api_key = ''
        QMessageBox.information(self, 'API Key Removed', 'API Key has been removed successfully.')

if __name__ == '__main__':
    import sys

    # Create the application
    app = QApplication(sys.argv)

    # Create and show the main window
    window = MainWindow()
    window.show()

    # Run the event loop
    sys.exit(app.exec_())

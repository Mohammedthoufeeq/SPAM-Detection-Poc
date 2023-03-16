import re
import socket
import threading
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QMessageBox
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QBrush, QColor


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.title = "Main Window"
        self.left = 100
        self.top = 100
        self.width = 640
        self.height = 480
        self.api_key = None
        self.sock = None
        self.port_input = QLineEdit()
        self.chat_history = []  # added

        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # Create input field and button for IP address
        self.ip_label = QLabel("Enter IP address:")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("xxx.xxx.xxx.xxx")

        self.ip_button = QPushButton("Connect")
        self.ip_button.clicked.connect(self.connect_to_server)

        # Create input field and button for port number
        self.port_label = QLabel("Enter port number:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("5000")
        self.port_button = QPushButton("Listen")
        self.port_button.clicked.connect(self.start_server)

        # Create text field to display messages
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)

        # Create input field and button for API key
        # Create the widgets for the API key
        self.api_label = QLabel("Enter API key:")
        self.api_input = QLineEdit()  # <-- Create QLineEdit widget
        self.api_input.setPlaceholderText("API key")

        # Add the API key widgets to a layout
        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(self.api_label)
        api_key_layout.addWidget(self.api_input)  # <-- Add QLineEdit widget

        # Create the buttons for setting/removing the API key
        self.set_api_key_button = QPushButton("Set API key")
        self.set_api_key_button.clicked.connect(self.set_api_key)
        self.remove_api_key_button = QPushButton("Remove API key")
        self.remove_api_key_button.clicked.connect(self.remove_api_key)

        # Set layout for the main window
        layout = QVBoxLayout()
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.ip_button)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.port_button)
        layout.addWidget(self.message_display)
        layout.addLayout(api_key_layout)  # <-- Add the API key layout
        layout.addWidget(self.set_api_key_button)
        layout.addWidget(self.remove_api_key_button)
        self.setLayout(layout)

    def remove_api_key(self):
        self.api_key = ''
        QMessageBox.information(self, 'API Key Removed', 'API Key has been removed successfully.')

    def set_api_key(self):
        api_key = self.api_input.text()
        if api_key:
            self.api_key = api_key
            QMessageBox.information(self, "API Key", "API key set successfully.")
        else:
            QMessageBox.warning(self, "API Key", "API key cannot be empty.")

    def remove_api_key(self):
        self.api_key = ''
        QMessageBox.information(self, 'API Key Removed', 'API Key has been removed successfully.')

    def handle_client_messages(self, client_socket):
        while client_socket:
            try:
                # Receive a message from the client
                message_bytes = client_socket.recv(1024)
                if not message_bytes:
                    break
                message = message_bytes.decode("utf-8").strip()
                # Add the message to the message display widget
                self.message_display.append(
                    f"{client_socket.getpeername()[0]}:{client_socket.getpeername()[1]} says: {message}")
            except OSError:
                break
        client_socket.close()

    def check_spam(self, message):
        # Check if message contains certain keywords
        keywords = [
            "100% free",
            "Act Now!",
            "As seen on",
            "Best price",
            "Bulk email",
            "Buy",
            "Cancel",
            "Cash",
            "Cheap",
            "Click",
            "Compare",
            "Credit",
            "Double your",
            "Earn",
            "Extra",
            "Fantastic",
            "Free",
            "Get",
            "Guarantee",
            "Hidden",
            "Increase",
            "Incredible",
            "Instant",
            "Investment",
            "Join",
            "Limited",
            "Luxury",
            "Make money",
            "Marketing",
            "Mass email",
            "Million",
            "Money",
            "Name brand",
            "New customers only",
            "Offer",
            "One time",
            "Opportunity",
            "Order",
            "Performance",
            "Pre-approved",
            "Price",
            "Promise",
            "Pure profit",
            "Refinance",
            "Removal",
            "Remove",
            "Reserves the right",
            "Sale",
            "Save",
            "Search engine listings",
            "See for yourself",
            "Sent in compliance",
            "Serious",
            "Subject to credit",
            "Supplies",
            "Take action",
            "Terms and conditions",
            "This isn't a scam",
            "This isn't spam",
            "Thousands",
            "Trial",
            "Unlimited",
            "Urgent",
            "US dollars",
            "Viagra",
            "We hate spam",
            "Web traffic",
            "Weekend getaway",
            "What are you waiting for?",
            "While supplies last",
            "Who really wins?",
            "Why pay more?",
            "Winner",
            "Work from home",
            "Xanax",
            "You are a winner!",
            "You have been selected",
            "You have been chosen",
            "Your income",
            "Zero risk",
            "$$$",
            "$$$s",
            "$$$,$$$",
            "$$$.$$$",
            "100% satisfied",
            "Act now!",
            "Additional income",
            "Affordable",
            "All natural",
            "Amazing",
            "Apply now",
            "Auto email removal",
            "Avoid",
            "Bargain",
            "Beneficiary",
            "Billing",
            "Billion",
            "Brand new pager",
            "Bulk",
            "Buy direct",
            "Cancel at any time",
            "Cents on the dollar",
            "Cheap",
            "Cheap cialis",
            "Check",
            "Claims",
            "Clearance",
            "Collect",
            "Compare",
            "Compete for your business",
            "Confidentiality",
            "Congratulations",
            "Consolidate debt and credit",
            "Copy accurately",
            "Cost",
            "Credit bureaus",
            "Credit card offers",
            "Cures",
            "Dear friend",
            "Degree",
            "Direct email",
            "Direct marketing",
            "Hidden charges",
            "Home",
            "Human growth hormone",
            "If only it were that easy",
            "Income",
            "Increase sales",
            "Increase traffic",
            "Increase your sales",
            "Incredible offer",
            "Insurance",
            "Internet market",
            "Investment",
            "Join millions",
            "Laser printer",
            "Lose",
            "Lose weight",
            "Lower rates",
            "Lower your mortgage rate",
            "Lowest price",
            "Luxury car",
            "Mail in order form",
            "Marketing solutions",
            "Mass email", "Rummy","rummy"]

        if any(keyword in message.lower() for keyword in keywords):
            return True

        # Check if message contains a URL
        url_pattern = r'http?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        url_match = re.search(url_pattern, message)
        if url_match:
            url = url_match.group(0)

            if not self.api_key:
                self.message_display.append("API key is not set. Please enter a valid API key.")
                return

            # Check URL with VirusTotal
            params = {'apikey': self.api_key, 'resource': url}
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            json_response = response.json()

            if json_response['response_code'] == 1:
                if json_response['positives'] > 0:
                    self.message_display.append("Message contains a malicious URL.")
                    return True
                else:
                    return False
            else:
                self.message_display.append("Unable to check URL. Please try again later.")
                return True

        return False

    def receive_message(self):
        while True:
            try:
                # Wait for a client to connect and accept the new socket
                client_socket, client_address = self.sock.accept()

                # Add a message to the display widget
                self.message_display.append(f"New client connected from {client_address[0]}:{client_address[1]}")

                # Receive messages from the client
                while True:
                    message = client_socket.recv(1024).decode('utf-8')
                    if message:
                        is_spam = self.check_spam(message)
                        if is_spam:
                            message = '<font color="red">' + message + '</font>'
                        self.message_display.append(message)
                    else:
                        # If the client closes the connection, add a message to the display widget
                        self.message_display.append(f"Client {client_address[0]}:{client_address[1]} has disconnected.")
                        client_socket.close()
                        break

            except OSError:
                break

    def start_server(self):
        if self.sock:
            self.message_display.append("Server already running.")
            return

        # Get the port number from the input field
        port_input_text = self.port_input.text()
        if not port_input_text:
            self.message_display.append("Please enter a valid port number.")
            return
        port_number = int(port_input_text)

        # Get the IP address from the input field
        ip_address = self.ip_input.text()
        if not ip_address:
            self.message_display.append("Please enter a valid IP address.")
            return

        # Add code here to start the server
        print(f"Starting server on {ip_address}:{port_number}...")

        try:
            # Create the server socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Bind the socket to the IP address and port number
            self.sock.bind((ip_address, port_number))

            # Start listening for incoming connections
            self.sock.listen(1)

            # Set up a thread to handle incoming messages
            self.receive_thread = threading.Thread(target=self.receive_message)
            self.receive_thread.start()

            self.message_display.append(f"Server started on {ip_address}:{port_number}.")
        except OSError as e:
            self.message_display.append(f"Error starting server: {e}")
            self.sock = None

    def connect_to_server(self):
        # Get the IP address from the input field
        ip_address = self.ip_input.text()
        if not ip_address:
            self.message_display.append("Please enter a valid IP address.")
            return

        # Get the port number from the input field
        port_input_text = self.port_input.text()
        if not port_input_text:
            self.message_display.append("Please enter a valid port number.")
            return
        port_number = int(port_input_text)

        # Create a socket and connect to the server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((ip_address, port_number))
            self.message_display.append(f"Connected to {ip_address}:{port_number}")
            # Start a thread to receive messages from the server
            threading.Thread(target=self.receive_message).start()
        except Exception as e:
            self.message_display.append(f"Error connecting to {ip_address}:{port_number}: {e}")
            self.sock = None

    def closeEvent(self, event):
        # Clean up resources when the window is closed
        if self.sock:
            self.sock.close()
            self.receive_thread.join()
        super().closeEvent(event)

if __name__ == '__main__':
    app = QApplication([])
    main_window = MainWindow()
    main_window.show()
    app.exec()

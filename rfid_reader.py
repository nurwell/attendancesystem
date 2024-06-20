import requests

def simulate_rfid_read(rfid_code):
    url = 'http://127.0.0.1:5000/attendance'
    data = {'rfid': rfid_code}
    response = requests.post(url, data=data)
    if response.status_code == 200:
        print("RFID read successfully recorded.")
    else:
        print("Failed to record RFID read.")

if __name__ == '__main__':
    simulate_rfid_read('1234567890')  # Example RFID code

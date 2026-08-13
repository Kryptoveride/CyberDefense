
import socket
import sys
import time

DEFAULT_PORT = 5555
DEFAULT_HOST = ""

SAMPLE_LINES = [
    b"2026-07-16 10:00:01 INFO User 'Jason' requested database access.\n",
    b"2026-07-16 10:00:04 INFO User 'Sarah' logged in successfully.\n",
    b"2026-07-16 10:00:07 WARNING Multiple failed login attempts for admin.\n",
    b"2026-07-16 10:00:10 ERROR Database connection failed.\n",
    b"2026-07-16 10:00:13 INFO HTTP GET /index.html returned status 200.\n",
    b"2026-07-16 10:00:16 CRITICAL Unauthorized privilege escalation detected.\n",
    b"2026-07-16 10:00:25 CRITICAL Malware detected in invoice.exe.\n",
]


def start_log_server(host=DEFAULT_HOST, port=DEFAULT_PORT, delay=2):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    print(f"[log_generator] Listening on port {port}")

    server_socket.listen(5)

    try:
        while True:
            conn, client_address = server_socket.accept()
            print(f"[log_generator] Connection from {client_address}")

            try:
                for line in SAMPLE_LINES:
                    conn.sendall(line)
                    time.sleep(delay)
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[log_generator] Shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    arg_port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    arg_host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    start_log_server(host=arg_host, port=arg_port)

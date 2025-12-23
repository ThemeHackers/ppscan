import http.server
import socketserver
import json

PORT = 8002

POLLUTED_STATUS = 400

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        global POLLUTED_STATUS
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON", "status": POLLUTED_STATUS}).encode())
                return

            user = {"username": "guest", "isAdmin": False}
            
            if "__proto__" in data:
                proto = data["__proto__"]
                for k, v in proto.items():
                    if k == "status" or k == "statusCode":
                        POLLUTED_STATUS = v
            
            if "constructor" in data and "prototype" in data["constructor"]:
                proto = data["constructor"]["prototype"]
                for k, v in proto.items():
                    if k == "status" or k == "statusCode":
                        POLLUTED_STATUS = v
            

            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(user).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            print(e)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()

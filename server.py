import http.server
import socketserver

PORT = 8000

class HttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        '.js':'application/javascript',
    }

httpd = socketserver.TCPServer(("localhost", PORT), HttpRequestHandler)

try:
    print(f"serving at http://localhost:{PORT}")
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

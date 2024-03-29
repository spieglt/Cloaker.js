import http.server

PORT = 8000

class HttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        '.js': 'application/javascript',
        '.html': 'text/html',
        '.css': 'text/css',
        '.svg': 'image/svg+xml',
        '.ico': 'image/vnd.microsoft.icon',
    }

httpd = http.server.HTTPServer(('', 8000), HttpRequestHandler)

try:
    print(f'serving at http://localhost:{PORT}')
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

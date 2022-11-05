from flask import *

app = Flask(__name__)

@app.route("/")
def home():
        print("Received")
        output = request.args.get('name')
        output = render_template_string(output)
        if output:
                pass
        else:
                output = "Test"
        return output

if __name__ == "__main__":
    print("Running...")
    app.run(debug=True, host="0.0.0.0", port=1337)
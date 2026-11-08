
from flask import Flask, render_template, jsonify
from scanner import scan_network, get_network_info

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/network-info")
def network_info():
    try:
        return jsonify({
            "success": True,
            "data": get_network_info()
        })
    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        result = scan_network()

        return jsonify({
            "success": True,
            "data": result
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

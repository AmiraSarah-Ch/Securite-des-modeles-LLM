from flask import Flask, render_template
from database import get_connection

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vulnerabilities")
def vulnerabilities():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities")
    data = cursor.fetchall()
    conn.close()
    return render_template("vulnerabilities.html", data=data)

@app.route("/vulnerability/<int:id>")
def vulnerability_detail(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities WHERE id=?", (id,))
    vuln = cursor.fetchone()
    conn.close()
    return render_template("vulnerability_detail.html", vuln=vuln)

if __name__ == "__main__":
    app.run(debug=True)

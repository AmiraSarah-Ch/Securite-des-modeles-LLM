from flask import Flask, render_template
from database import VulnerabilityDB

app = Flask(__name__)
db = VulnerabilityDB()  # Instance de la base de données

@app.route("/")
def index():
    # Page d'accueil simple
    return render_template("index.html")

@app.route("/vulnerabilities")
def vulnerabilities():
    # Récupérer toutes les vulnérabilités de packages
    data = db.get_all_packages().to_dict(orient='records')  # DataFrame -> liste de dicts
    return render_template("vulnerabilities.html", data=data)

@app.route("/vulnerability/<int:id>")
def vulnerability_detail(id):
    # Chercher la vulnérabilité correspondant à l'ID
    data = db.get_all_packages()
    vuln = data[data['id'] == id].to_dict(orient='records')
    vuln = vuln[0] if vuln else None
    return render_template("vulnerability_detail.html", vuln=vuln)

if __name__ == "__main__":
    app.run(debug=True)

# VTBDA – Veille Sécurité LLM

Outil de veille technologique pour surveiller les vulnérabilités des modèles de langage (LLM).  
Il permet de stocker, analyser et visualiser les vulnérabilités détectées.

## Fonctionnalités

- Base de données SQLite pour stocker les vulnérabilités
- Analyse des vulnérabilités par catégorie et impact
- Interface web Flask pour consulter et visualiser les informations
- Possibilité d’ajouter de nouvelles vulnérabilités via le code

Installer les dépendances :

pip install -r requirements.txt


Initialiser la base et ajouter les données de test :

python database.py
python add_test_data.py


Lancer l’application Flask :

python app.py

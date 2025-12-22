from database import get_connection
from datetime import datetime

data = [
    ("Prompt Injection", "Attaque", "Manipulation des prompts utilisateur", "Élevé", "OWASP"),
    ("Data Leakage", "Fuite", "Divulgation de données sensibles", "Élevé", "Arxiv"),
    ("Jailbreak", "Contournement", "Contournement des règles du LLM", "Moyen", "Blog Sécurité")
]

conn = get_connection()
cursor = conn.cursor()

for d in data:
    cursor.execute("""
        INSERT INTO vulnerabilities (name, category, description, impact, source, date_added)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (*d, datetime.now().isoformat()))

conn.commit()
conn.close()

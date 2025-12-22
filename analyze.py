from database import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("SELECT category, COUNT(*) FROM vulnerabilities GROUP BY category")
results = cursor.fetchall()

print("Analyse des vulnérabilités par catégorie:")
for r in results:
    print(f"{r[0]} : {r[1]}")

conn.close()

import sqlite3
import pandas as pd
from datetime import datetime
import os

class VulnerabilityDB:
    """
    Classe pour gérer la base de données des vulnérabilités
    """
    
    def __init__(self, db_name='data/vulnerabilities.db'):
        """
        Initialiser la connexion à la base de données
        
        Args:
            db_name: Chemin vers le fichier .db
        """
        self.db_name = db_name
        
        # Créer dossier data/ s'il n'existe pas
        os.makedirs('data', exist_ok=True)
        
        # Créer tables si elles n'existent pas
        self.create_tables()
        print(f"✅ Base de données initialisée : {db_name}")
    
    def create_tables(self):
        """
        Créer les 3 tables nécessaires
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # TABLE 1 : CVE (vulnérabilités générales de NVD)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            cvss_score REAL,
            severity TEXT CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
            published_date TEXT,
            source TEXT DEFAULT 'NVD',
            url TEXT,
            collected_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # TABLE 2 : PACKAGES (npm, pip, maven, docker)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS package_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT CHECK(ecosystem IN ('npm','pip','maven','docker','kubernetes','github')),
            vulnerability_type TEXT,
            cvss_score REAL,
            severity TEXT CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
            description TEXT,
            published_date TEXT,
            affected_versions TEXT,
            patched_version TEXT,
            source TEXT,
            url TEXT,
            collected_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # TABLE 3 : SUPPLY-CHAIN (dépendances entre packages)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS supply_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_package TEXT NOT NULL,
            dependent_package TEXT NOT NULL,
            ecosystem TEXT,
            vulnerability_id INTEGER,
            impact_score INTEGER DEFAULT 0,
            FOREIGN KEY(vulnerability_id) REFERENCES package_vulnerabilities(id)
        )
        ''')
        
        # Index pour accélérer les recherches
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON package_vulnerabilities(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ecosystem ON package_vulnerabilities(ecosystem)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_package_name ON package_vulnerabilities(package_name)')
        
        conn.commit()
        conn.close()
        print("✅ Tables créées avec succès")
    
    # ========== FONCTIONS INSERT (Ajouter données) ==========
    
    def insert_cve(self, cve_data):
        """
        Ajouter une vulnérabilité CVE
        
        Args:
            cve_data: Dictionnaire avec clés : cve_id, description, cvss_score, severity, published_date, url
        
        Returns:
            True si succès, False sinon
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT OR IGNORE INTO cve_vulnerabilities 
            (cve_id, description, cvss_score, severity, published_date, url)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                cve_data.get('cve_id'),
                cve_data.get('description'),
                cve_data.get('cvss_score'),
                cve_data.get('severity'),
                cve_data.get('published_date'),
                cve_data.get('url')
            ))
            conn.commit()
            print(f"✅ CVE ajouté : {cve_data.get('cve_id')}")
            return True
        except Exception as e:
            print(f"❌ Erreur insertion CVE : {e}")
            return False
        finally:
            conn.close()
    
    def insert_package_vulnerability(self, package_data):
        """
        Ajouter une vulnérabilité de package
        
        Args:
            package_data: Dictionnaire avec clés : package_name, ecosystem, vulnerability_type, 
                         cvss_score, severity, description, published_date, affected_versions, 
                         patched_version, source, url
        
        Returns:
            ID de la vulnérabilité insérée ou None
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO package_vulnerabilities 
            (package_name, ecosystem, vulnerability_type, cvss_score, severity, 
             description, published_date, affected_versions, patched_version, source, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                package_data.get('package_name'),
                package_data.get('ecosystem'),
                package_data.get('vulnerability_type'),
                package_data.get('cvss_score'),
                package_data.get('severity'),
                package_data.get('description'),
                package_data.get('published_date'),
                package_data.get('affected_versions'),
                package_data.get('patched_version'),
                package_data.get('source'),
                package_data.get('url')
            ))
            conn.commit()
            vuln_id = cursor.lastrowid  # Récupérer ID de la ligne insérée
            print(f"✅ Package ajouté : {package_data.get('package_name')}")
            return vuln_id
        except Exception as e:
            print(f"❌ Erreur insertion package : {e}")
            return None
        finally:
            conn.close()
    
    def insert_supply_chain(self, parent_package, dependent_package, ecosystem, vulnerability_id=None):
        """
        Ajouter une relation de dépendance
        
        Args:
            parent_package: Package parent (qui utilise)
            dependent_package: Package dépendant (qui est utilisé)
            ecosystem: npm, pip, maven...
            vulnerability_id: ID de la vulnérabilité associée
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO supply_chain 
            (parent_package, dependent_package, ecosystem, vulnerability_id)
            VALUES (?, ?, ?, ?)
            ''', (parent_package, dependent_package, ecosystem, vulnerability_id))
            conn.commit()
            print(f"✅ Relation supply-chain ajoutée : {parent_package} → {dependent_package}")
            return True
        except Exception as e:
            print(f"❌ Erreur insertion supply-chain : {e}")
            return False
        finally:
            conn.close()
    
    # ========== FONCTIONS GET (Récupérer données) ==========
    
    def get_all_cve(self):
        """
        Récupérer toutes les CVE
        
        Returns:
            DataFrame pandas avec toutes les CVE
        """
        conn = sqlite3.connect(self.db_name)
        df = pd.read_sql_query("SELECT * FROM cve_vulnerabilities ORDER BY published_date DESC", conn)
        conn.close()
        return df
    
    def get_all_packages(self):
        """
        Récupérer toutes les vulnérabilités de packages
        
        Returns:
            DataFrame pandas
        """
        conn = sqlite3.connect(self.db_name)
        df = pd.read_sql_query("SELECT * FROM package_vulnerabilities ORDER BY published_date DESC", conn)
        conn.close()
        return df
    
    def get_packages_by_severity(self, severity):
        """
        Filtrer packages par sévérité
        
        Args:
            severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
        
        Returns:
            DataFrame filtré
        """
        conn = sqlite3.connect(self.db_name)
        query = "SELECT * FROM package_vulnerabilities WHERE severity = ? ORDER BY cvss_score DESC"
        df = pd.read_sql_query(query, conn, params=(severity,))
        conn.close()
        return df
    
    def get_packages_by_ecosystem(self, ecosystem):
        """
        Filtrer par écosystème (npm, pip, maven...)
        
        Args:
            ecosystem: 'npm', 'pip', 'maven', 'docker', 'kubernetes'
        
        Returns:
            DataFrame filtré
        """
        conn = sqlite3.connect(self.db_name)
        query = "SELECT * FROM package_vulnerabilities WHERE ecosystem = ? ORDER BY published_date DESC"
        df = pd.read_sql_query(query, conn, params=(ecosystem,))
        conn.close()
        return df
    
    def search_package(self, package_name):
        """
        Rechercher un package spécifique
        
        Args:
            package_name: Nom du package (ex: 'lodash', 'django')
        
        Returns:
            DataFrame avec résultats
        """
        conn = sqlite3.connect(self.db_name)
        query = "SELECT * FROM package_vulnerabilities WHERE package_name LIKE ?"
        df = pd.read_sql_query(query, conn, params=(f'%{package_name}%',))
        conn.close()
        return df
    
    def get_supply_chain_impact(self, package_name):
        """
        Trouver tous les packages qui dépendent d'un package donné
        CRITIQUE pour analyse supply-chain
        
        Args:
            package_name: Nom du package compromis
        
        Returns:
            DataFrame avec liste des packages impactés
        """
        conn = sqlite3.connect(self.db_name)
        query = '''
        SELECT sc.parent_package, sc.dependent_package, sc.ecosystem, 
               pv.severity, pv.cvss_score, pv.description
        FROM supply_chain sc
        LEFT JOIN package_vulnerabilities pv ON sc.vulnerability_id = pv.id
        WHERE sc.dependent_package = ?
        '''
        df = pd.read_sql_query(query, conn, params=(package_name,))
        conn.close()
        return df
    
    # ========== FONCTIONS UTILITAIRES ==========
    
    def get_total_count(self):
        """
        Compter total de vulnérabilités
        
        Returns:
            Dictionnaire avec compteurs
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities")
        cve_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM package_vulnerabilities")
        package_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'cve_count': cve_count,
            'package_count': package_count,
            'total': cve_count + package_count
        }
    
    def clear_all_data(self):
        """
        ATTENTION : Supprimer TOUTES les données (pour tests)
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM cve_vulnerabilities")
        cursor.execute("DELETE FROM package_vulnerabilities")
        cursor.execute("DELETE FROM supply_chain")
        
        conn.commit()
        conn.close()
        print("⚠️ Toutes les données supprimées")


# ========== SCRIPT DE TEST ==========
if __name__ == "__main__":
    """
    Ce code s'exécute uniquement si vous lancez : python database.py
    Permet de tester les fonctions
    """
    
    print("=== TEST DATABASE.PY ===\n")
    
    # Créer instance de la BDD
    db = VulnerabilityDB()
    
    # TEST 1 : Insérer une CVE
    print("\n--- Test 1 : Insertion CVE ---")
    test_cve = {
        'cve_id': 'CVE-2024-TEST-001',
        'description': 'Vulnérabilité test pour démonstration',
        'cvss_score': 8.5,
        'severity': 'HIGH',
        'published_date': '2024-12-22',
        'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-TEST-001'
    }
    db.insert_cve(test_cve)
    
    # TEST 2 : Insérer un package vulnérable
    print("\n--- Test 2 : Insertion Package ---")
    test_package = {
        'package_name': 'lodash',
        'ecosystem': 'npm',
        'vulnerability_type': 'prototype pollution',
        'cvss_score': 9.1,
        'severity': 'CRITICAL',
        'description': 'Prototype pollution vulnerability in lodash',
        'published_date': '2024-12-20',
        'affected_versions': '< 4.17.21',
        'patched_version': '4.17.21',
        'source': 'GitHub Advisory',
        'url': 'https://github.com/advisories/GHSA-xxxx'
    }
    vuln_id = db.insert_package_vulnerability(test_package)
    
    # TEST 3 : Insérer relation supply-chain
    print("\n--- Test 3 : Insertion Supply-chain ---")
    db.insert_supply_chain('react-scripts', 'lodash', 'npm', vuln_id)
    db.insert_supply_chain('webpack', 'lodash', 'npm', vuln_id)
    
    # TEST 4 : Récupérer données
    print("\n--- Test 4 : Récupération données ---")
    all_packages = db.get_all_packages()
    print(f"Nombre de packages : {len(all_packages)}")
    
    # TEST 5 : Recherche
    print("\n--- Test 5 : Recherche 'lodash' ---")
    results = db.search_package('lodash')
    print(f"Résultats trouvés : {len(results)}")
    
    # TEST 6 : Impact supply-chain
    print("\n--- Test 6 : Impact supply-chain de 'lodash' ---")
    impact = db.get_supply_chain_impact('lodash')
    print(f"Packages impactés : {len(impact)}")
    if len(impact) > 0:
        print(impact[['parent_package', 'severity', 'cvss_score']])
    
    # TEST 7 : Statistiques
    print("\n--- Test 7 : Statistiques ---")
    stats = db.get_total_count()
    print(f"Total CVE : {stats['cve_count']}")
    print(f"Total Packages : {stats['package_count']}")
    print(f"Total général : {stats['total']}")
    
    print("\n✅ TOUS LES TESTS RÉUSSIS !")
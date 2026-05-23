"""
MediRural — Application Flask complète
Backend + Frontend intégré, SQLite, JWT, Téléconsultation, IA
"""
import sqlite3, hashlib, os, json, re
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, g, flash)
import jwt as pyjwt

# ── Config ────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "medirural_secret_2025"
JWT_SECRET     = "medirural_jwt_2025"
DB_PATH        = os.path.join(os.path.dirname(__file__), "medirural.db")

# ── DB helpers ────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv  = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid

# ── Hash mot de passe ─────────────────────────────────────────
def hash_pwd(pwd):
    return hashlib.sha256((pwd + app.secret_key).encode()).hexdigest()

# ── JWT ───────────────────────────────────────────────────────
def make_token(user_id, role):
    payload = {"user_id": user_id, "role": role,
               "exp": datetime.utcnow() + timedelta(days=7)}
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token):
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

# ── Auth decorators ───────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("Accès non autorisé", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator

def api_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        if not token:
            return jsonify({"error": "Token manquant"}), 401
        data = decode_token(token)
        if not data:
            return jsonify({"error": "Token invalide"}), 401
        g.user_id = data["user_id"]
        g.role    = data["role"]
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════
# INIT DB
# ══════════════════════════════════════════════════════════════
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            name        TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'patient',
            age         INTEGER,
            city        TEXT,
            phone       TEXT,
            specialite  TEXT,
            bio         TEXT,
            avatar_color TEXT DEFAULT '#0097A7',
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS doctors (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL UNIQUE,
            specialite  TEXT NOT NULL,
            note        REAL DEFAULT 4.8,
            nb_consults INTEGER DEFAULT 0,
            dispo       TEXT DEFAULT 'Disponible',
            tarif       INTEGER DEFAULT 25,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS consultations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            doctor_id   INTEGER NOT NULL,
            motif       TEXT,
            status      TEXT DEFAULT 'planifiee',
            date_rdv    TEXT,
            notes       TEXT,
            ordonnance  TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id)  REFERENCES doctors(id)
        );

        CREATE TABLE IF NOT EXISTS ordonnances (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            doctor_id   INTEGER NOT NULL,
            medicament  TEXT NOT NULL,
            posologie   TEXT,
            duree       TEXT,
            status      TEXT DEFAULT 'en_attente',
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id)  REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS constantes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            tension     TEXT,
            glycemie    TEXT,
            poids       REAL,
            temperature REAL,
            spo2        TEXT,
            recorded_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (patient_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_id     INTEGER NOT NULL,
            to_id       INTEGER NOT NULL,
            content     TEXT NOT NULL,
            lu          INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (from_id) REFERENCES users(id),
            FOREIGN KEY (to_id)   REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS avis (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            doctor_id   INTEGER NOT NULL,
            note        INTEGER CHECK(note BETWEEN 1 AND 5),
            commentaire TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id)  REFERENCES doctors(id)
        );
    """)

    # Seed si vide
    if not db.execute("SELECT id FROM users LIMIT 1").fetchone():
        _seed(db)
    db.commit()
    db.close()

def _seed(db):
    h = lambda p: hashlib.sha256((p + app.secret_key).encode()).hexdigest()

    users = [
        ("marie@test.com",   h("test123"), "Marie Dupont",    "patient", 58, "Aurillac (15)",  "06 10 11 12 13", None,                   None,                              "#0097A7"),
        ("jean@test.com",    h("test123"), "Jean Morel",      "patient", 72, "Aurillac (15)",  "06 10 22 33 44", None,                   None,                              "#1565C0"),
        ("claire@test.com",  h("test123"), "Claire Roussel",  "patient", 45, "Saint-Flour",    "06 30 44 55 66", None,                   None,                              "#2E7D32"),
        ("kone@test.com",    h("test123"), "Dr. Amina Koné",  "doctor",  42, "Aurillac (15)",  "04 71 00 11 22", "Médecin généraliste",  "Médecin généraliste depuis 12 ans, spécialisée en maladies chroniques et suivi rural.", "#0097A7"),
        ("renard@test.com",  h("test123"), "Dr. Paul Renard", "doctor",  55, "Aurillac (15)",  "04 71 00 33 44", "Cardiologue",          "Cardiologue interventionnel, ancien chef de service au CHU de Clermont-Ferrand.",        "#1565C0"),
        ("mbaye@test.com",   h("test123"), "Dr. Sara Mbaye",  "doctor",  38, "Saint-Flour",    "04 71 00 55 66", "Diabétologue",         "Diabétologue et endocrinologue, passionnée par la prévention des maladies métaboliques.", "#2E7D32"),
        ("hadj@test.com",    h("test123"), "Dr. Karim Hadj",  "doctor",  47, "Aurillac (15)",  "04 71 00 77 88", "Pneumologue",          "Pneumologue spécialisé en BPCO, asthme et pathologies respiratoires.",                  "#F9A825"),
    ]
    db.executemany(
        "INSERT INTO users(email,password,name,role,age,city,phone,specialite,bio,avatar_color) VALUES(?,?,?,?,?,?,?,?,?,?)",
        users
    )

    doctors = [
        (4, "Médecin généraliste", 4.9, 1240, "Disponible",        25),
        (5, "Cardiologue",         4.8, 892,  "Disponible · 45min", 50),
        (6, "Diabétologue",        4.9, 1102, "Demain · 9h00",     45),
        (7, "Pneumologue",         4.7, 678,  "Aujourd'hui · 17h", 45),
    ]
    db.executemany(
        "INSERT INTO doctors(user_id,specialite,note,nb_consults,dispo,tarif) VALUES(?,?,?,?,?,?)",
        doctors
    )

    # Consultations patient 1
    db.executemany("INSERT INTO consultations(patient_id,doctor_id,motif,status,date_rdv,notes) VALUES(?,?,?,?,?,?)", [
        (1, 1, "Suivi diabète",       "terminee",  "2025-05-18 10:30", "Glycémie stable. Continuer Metformine. Prochain contrôle HbA1c dans 3 mois."),
        (1, 1, "Bilan annuel",        "terminee",  "2025-04-05 11:00", "Bilan général satisfaisant. Légère augmentation de la tension artérielle."),
        (1, 2, "Bilan cardiologique", "terminee",  "2025-05-05 14:00", "ECG normal. Pas d'anomalie détectée. Continuer Amlodipine."),
        (1, 1, "Suivi diabète",       "planifiee", "2025-05-23 10:30", None),
    ])

    # Ordonnances
    db.executemany("INSERT INTO ordonnances(patient_id,doctor_id,medicament,posologie,duree,status) VALUES(?,?,?,?,?,?)", [
        (1, 4, "Metformine 500mg",   "1 cp matin et soir",  "30 jours", "livre"),
        (1, 4, "Amlodipine 5mg",     "1 cp le matin",       "30 jours", "en_cours"),
        (1, 5, "Vitamine D3 1000UI", "1 cp par jour",       "60 jours", "prepare"),
        (2, 4, "Ramipril 5mg",       "1 cp le soir",        "30 jours", "en_attente"),
    ])

    # Constantes patient 1
    db.executemany("INSERT INTO constantes(patient_id,tension,glycemie,poids,temperature,spo2) VALUES(?,?,?,?,?,?)", [
        (1, "128/82", "6.2", 71.0, 37.0, "98%"),
        (1, "130/85", "6.5", 71.2, 36.8, "97%"),
        (1, "125/80", "6.1", 70.8, 37.1, "98%"),
    ])

    # Avis
    db.executemany("INSERT INTO avis(patient_id,doctor_id,note,commentaire) VALUES(?,?,?,?)", [
        (1, 1, 5, "Très à l'écoute, consultation rapide et efficace."),
        (2, 1, 5, "Médecin excellente, explique bien et rassure."),
        (1, 2, 5, "Cardiologue très compétent, bilan très complet."),
    ])


# ══════════════════════════════════════════════════════════════
# ROUTES PAGES HTML
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email","").strip()
        pwd   = request.form.get("password","")
        user  = query("SELECT * FROM users WHERE email=?", (email,), one=True)
        if user and user["password"] == hash_pwd(pwd):
            session["user_id"] = user["id"]
            session["role"]    = user["role"]
            session["name"]    = user["name"]
            session["email"]   = user["email"]
            session["avatar_color"] = user["avatar_color"]
            return redirect(url_for("dashboard"))
        flash("Email ou mot de passe incorrect", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email     = request.form.get("email","").strip()
        pwd       = request.form.get("password","")
        name      = request.form.get("name","").strip()
        role      = request.form.get("role","patient")
        age       = request.form.get("age","")
        city      = request.form.get("city","").strip()
        phone     = request.form.get("phone","").strip()
        specialite= request.form.get("specialite","").strip()

        if not email or not pwd or not name:
            flash("Veuillez remplir tous les champs obligatoires", "error")
            return render_template("register.html")
        if query("SELECT id FROM users WHERE email=?", (email,), one=True):
            flash("Cet email est déjà utilisé", "error")
            return render_template("register.html")

        colors = ["#0097A7","#1565C0","#2E7D32","#7B1FA2","#E65100"]
        import random
        color = random.choice(colors)
        execute(
            "INSERT INTO users(email,password,name,role,age,city,phone,specialite,avatar_color) VALUES(?,?,?,?,?,?,?,?,?)",
            (email, hash_pwd(pwd), name, role, age or None, city or None, phone or None, specialite or None, color)
        )
        user = query("SELECT * FROM users WHERE email=?", (email,), one=True)
        if role == "doctor":
            execute("INSERT INTO doctors(user_id,specialite) VALUES(?,?)",
                    (user["id"], specialite or "Généraliste"))

        session["user_id"] = user["id"]
        session["role"]    = user["role"]
        session["name"]    = user["name"]
        session["email"]   = user["email"]
        session["avatar_color"] = color
        flash(f"Bienvenue {name} ! Votre compte a été créé.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid  = session["user_id"]
    role = session["role"]
    if role == "patient":
        user   = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
        consults = query("""
            SELECT c.*, u.name as doc_name, d.specialite
            FROM consultations c
            JOIN doctors d ON c.doctor_id=d.id
            JOIN users u ON d.user_id=u.id
            WHERE c.patient_id=? ORDER BY c.date_rdv DESC LIMIT 5
        """, (uid,))
        ordos = query("""
            SELECT o.*, u.name as doc_name FROM ordonnances o
            JOIN users u ON o.doctor_id=u.id
            WHERE o.patient_id=? ORDER BY o.created_at DESC LIMIT 3
        """, (uid,))
        constante = query("SELECT * FROM constantes WHERE patient_id=? ORDER BY recorded_at DESC LIMIT 1", (uid,), one=True)
        prochain  = query("""
            SELECT c.*, u.name as doc_name FROM consultations c
            JOIN doctors d ON c.doctor_id=d.id
            JOIN users u ON d.user_id=u.id
            WHERE c.patient_id=? AND c.status='planifiee' ORDER BY c.date_rdv ASC LIMIT 1
        """, (uid,), one=True)
        return render_template("dashboard_patient.html",
            user=user, consults=consults, ordos=ordos,
            constante=constante, prochain=prochain)
    else:
        doc = query("SELECT * FROM doctors WHERE user_id=?", (uid,), one=True)
        if not doc:
            flash("Profil médecin introuvable", "error")
            return redirect(url_for("logout"))
        patients_today = query("""
            SELECT c.*, u.name as patient_name, u.age as patient_age
            FROM consultations c JOIN users u ON c.patient_id=u.id
            WHERE c.doctor_id=? AND date(c.date_rdv)=date('now')
            ORDER BY c.date_rdv ASC
        """, (doc["id"],))
        ordos_pending = query("""
            SELECT o.*, u.name as patient_name FROM ordonnances o
            JOIN users u ON o.patient_id=u.id
            WHERE o.doctor_id=? AND o.status='en_attente'
        """, (uid,))
        stats = {
            "total": query("SELECT COUNT(*) as n FROM consultations WHERE doctor_id=?", (doc["id"],), one=True)["n"],
            "today": len(patients_today),
            "note":  doc["note"],
            "ordos": len(ordos_pending)
        }
        return render_template("dashboard_medecin.html",
            doc=doc, patients_today=patients_today,
            ordos_pending=ordos_pending, stats=stats)

@app.route("/doctors")
@login_required
def doctors():
    search = request.args.get("q","").strip()
    spec   = request.args.get("spec","").strip()
    sql    = """
        SELECT d.*, u.name, u.city, u.bio, u.avatar_color
        FROM doctors d JOIN users u ON d.user_id=u.id
        WHERE 1=1
    """
    args = []
    if search:
        sql += " AND (u.name LIKE ? OR d.specialite LIKE ?)"
        args += [f"%{search}%", f"%{search}%"]
    if spec:
        sql += " AND d.specialite=?"
        args.append(spec)
    sql += " ORDER BY d.note DESC"
    docs = query(sql, args)
    specs = query("SELECT DISTINCT specialite FROM doctors ORDER BY specialite")
    return render_template("doctors.html", doctors=docs, specs=specs, search=search, spec=spec)

@app.route("/doctors/<int:doc_id>")
@login_required
def doctor_detail(doc_id):
    doc  = query("SELECT d.*,u.name,u.city,u.bio,u.avatar_color,u.phone FROM doctors d JOIN users u ON d.user_id=u.id WHERE d.id=?", (doc_id,), one=True)
    if not doc:
        flash("Médecin introuvable", "error")
        return redirect(url_for("doctors"))
    avis_list = query("""
        SELECT a.*, u.name as patient_name FROM avis a
        JOIN users u ON a.patient_id=u.id
        WHERE a.doctor_id=? ORDER BY a.created_at DESC LIMIT 5
    """, (doc_id,))
    return render_template("doctor_detail.html", doc=doc, avis=avis_list)

@app.route("/book/<int:doc_id>", methods=["GET","POST"])
@login_required
@role_required("patient")
def book(doc_id):
    doc = query("SELECT d.*,u.name,u.avatar_color FROM doctors d JOIN users u ON d.user_id=u.id WHERE d.id=?", (doc_id,), one=True)
    if not doc:
        flash("Médecin introuvable", "error")
        return redirect(url_for("doctors"))
    if request.method == "POST":
        motif   = request.form.get("motif","").strip()
        date_rv = request.form.get("date_rdv","")
        if not motif or not date_rv:
            flash("Veuillez remplir tous les champs", "error")
            now = datetime.now().strftime("%Y-%m-%dT%H:%M")
            default_date = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
            return render_template("book.html", doc=doc, now=now, default_date=default_date)
        execute("""
            INSERT INTO consultations(patient_id,doctor_id,motif,date_rdv,status)
            VALUES(?,?,?,?,?)
        """, (session["user_id"], doc_id, motif, date_rv, "planifiee"))
        execute("UPDATE doctors SET nb_consults=nb_consults+1 WHERE id=?", (doc_id,))
        flash("Rendez-vous confirmé ! Vous recevrez un rappel.", "success")
        return redirect(url_for("consultations"))
    now = datetime.now().strftime("%Y-%m-%dT%H:%M")
    default_date = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
    return render_template("book.html", doc=doc, now=now, default_date=default_date)

@app.route("/consultations")
@login_required
def consultations():
    uid  = session["user_id"]
    role = session["role"]
    if role == "patient":
        rows = query("""
            SELECT c.*, u.name as doc_name, d.specialite, u.avatar_color
            FROM consultations c
            JOIN doctors d ON c.doctor_id=d.id
            JOIN users u ON d.user_id=u.id
            WHERE c.patient_id=? ORDER BY c.date_rdv DESC
        """, (uid,))
    else:
        doc = query("SELECT id FROM doctors WHERE user_id=?", (uid,), one=True)
        rows = query("""
            SELECT c.*, u.name as patient_name, u.age as patient_age, u.city as patient_city
            FROM consultations c JOIN users u ON c.patient_id=u.id
            WHERE c.doctor_id=? ORDER BY c.date_rdv DESC
        """, (doc["id"],)) if doc else []
    return render_template("consultations.html", consultations=rows)

@app.route("/teleconsult/<int:consult_id>")
@login_required
def teleconsult(consult_id):
    uid  = session["user_id"]
    role = session["role"]
    c = query("SELECT c.*,u.name as doc_name,d.specialite,u.avatar_color FROM consultations c JOIN doctors d ON c.doctor_id=d.id JOIN users u ON d.user_id=u.id WHERE c.id=?", (consult_id,), one=True)
    if not c:
        flash("Consultation introuvable", "error")
        return redirect(url_for("consultations"))
    patient = query("SELECT * FROM users WHERE id=?", (c["patient_id"],), one=True)
    return render_template("teleconsult.html", consult=c, patient=patient)

@app.route("/ordonnances")
@login_required
def ordonnances():
    uid  = session["user_id"]
    role = session["role"]
    if role == "patient":
        rows = query("""
            SELECT o.*, u.name as doc_name FROM ordonnances o
            JOIN users u ON o.doctor_id=u.id
            WHERE o.patient_id=? ORDER BY o.created_at DESC
        """, (uid,))
    else:
        rows = query("""
            SELECT o.*, u.name as patient_name FROM ordonnances o
            JOIN users u ON o.patient_id=u.id
            WHERE o.doctor_id=? ORDER BY o.created_at DESC
        """, (uid,))
    return render_template("ordonnances.html", ordonnances=rows)

@app.route("/ordonnances/new", methods=["GET","POST"])
@login_required
@role_required("doctor")
def new_ordonnance():
    if request.method == "POST":
        pid  = request.form.get("patient_id")
        med  = request.form.get("medicament","").strip()
        pos  = request.form.get("posologie","").strip()
        dur  = request.form.get("duree","").strip()
        if not pid or not med:
            flash("Champs requis manquants", "error")
        else:
            execute("INSERT INTO ordonnances(patient_id,doctor_id,medicament,posologie,duree) VALUES(?,?,?,?,?)",
                    (pid, session["user_id"], med, pos, dur))
            flash("Ordonnance créée avec succès", "success")
            return redirect(url_for("ordonnances"))
    patients = query("SELECT id,name FROM users WHERE role='patient' ORDER BY name")
    return render_template("new_ordonnance.html", patients=patients)

@app.route("/constantes", methods=["GET","POST"])
@login_required
@role_required("patient")
def constantes():
    uid = session["user_id"]
    if request.method == "POST":
        t   = request.form.get("tension","").strip()
        g_v = request.form.get("glycemie","").strip()
        p   = request.form.get("poids","")
        tmp = request.form.get("temperature","")
        s   = request.form.get("spo2","").strip()
        execute("INSERT INTO constantes(patient_id,tension,glycemie,poids,temperature,spo2) VALUES(?,?,?,?,?,?)",
                (uid, t or None, g_v or None, p or None, tmp or None, s or None))
        flash("Constantes enregistrées", "success")
        return redirect(url_for("constantes"))
    rows = query("SELECT * FROM constantes WHERE patient_id=? ORDER BY recorded_at DESC LIMIT 15", (uid,))
    return render_template("constantes.html", constantes=rows)

@app.route("/messages")
@login_required
def messages():
    uid = session["user_id"]
    role = session["role"]
    if role == "patient":
        contacts = query("""
            SELECT DISTINCT u.id,u.name,u.avatar_color,d.specialite FROM doctors d
            JOIN users u ON d.user_id=u.id ORDER BY u.name
        """)
    else:
        contacts = query("SELECT id,name,avatar_color,NULL as specialite FROM users WHERE role='patient' ORDER BY name")
    return render_template("messages.html", contacts=contacts)

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    uid = session["user_id"]
    if request.method == "POST":
        name  = request.form.get("name","").strip()
        city  = request.form.get("city","").strip()
        phone = request.form.get("phone","").strip()
        age   = request.form.get("age","")
        bio   = request.form.get("bio","").strip()
        execute("UPDATE users SET name=?,city=?,phone=?,age=?,bio=? WHERE id=?",
                (name, city, phone, age or None, bio, uid))
        session["name"] = name
        flash("Profil mis à jour", "success")
    user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    return render_template("profile.html", user=user)

@app.route("/assistant")
@login_required
def assistant():
    return render_template("assistant.html")

# ══════════════════════════════════════════════════════════════
# API JSON (pour appels JS)
# ══════════════════════════════════════════════════════════════

@app.route("/api/messages/<int:to_id>", methods=["GET"])
@login_required
def api_get_messages(to_id):
    uid = session["user_id"]
    rows = query("""
        SELECT m.*,u.name as from_name FROM messages m
        JOIN users u ON m.from_id=u.id
        WHERE (m.from_id=? AND m.to_id=?) OR (m.from_id=? AND m.to_id=?)
        ORDER BY m.created_at ASC
    """, (uid, to_id, to_id, uid))
    execute("UPDATE messages SET lu=1 WHERE to_id=? AND from_id=?", (uid, to_id))
    return jsonify([dict(r) for r in rows])

@app.route("/api/messages", methods=["POST"])
@login_required
def api_send_message():
    data    = request.get_json()
    to_id   = data.get("to_id")
    content = data.get("content","").strip()
    if not to_id or not content:
        return jsonify({"error": "Champs manquants"}), 400
    uid = session["user_id"]
    rid = execute("INSERT INTO messages(from_id,to_id,content) VALUES(?,?,?)",
                  (uid, to_id, content))
    msg = query("SELECT m.*,u.name as from_name FROM messages m JOIN users u ON m.from_id=u.id WHERE m.id=?", (rid,), one=True)
    return jsonify(dict(msg))

@app.route("/api/constantes", methods=["GET"])
@login_required
def api_constantes():
    uid  = session["user_id"]
    rows = query("SELECT * FROM constantes WHERE patient_id=? ORDER BY recorded_at ASC LIMIT 10", (uid,))
    return jsonify([dict(r) for r in rows])

@app.route("/api/consultation/<int:cid>/finish", methods=["POST"])
@login_required
@role_required("doctor")
def api_finish_consult(cid):
    data  = request.get_json()
    notes = data.get("notes","")
    execute("UPDATE consultations SET status='terminee',notes=? WHERE id=?", (notes, cid))
    return jsonify({"ok": True})

@app.route("/api/ordonnance/<int:oid>/status", methods=["POST"])
@login_required
def api_update_ordo_status(oid):
    data   = request.get_json()
    status = data.get("status")
    execute("UPDATE ordonnances SET status=? WHERE id=?", (status, oid))
    return jsonify({"ok": True})

@app.route("/api/avis", methods=["POST"])
@login_required
@role_required("patient")
def api_add_avis():
    data = request.get_json()
    execute("INSERT INTO avis(patient_id,doctor_id,note,commentaire) VALUES(?,?,?,?)",
            (session["user_id"], data["doctor_id"], data["note"], data.get("commentaire","")))
    execute("UPDATE doctors SET note=(SELECT AVG(note) FROM avis WHERE doctor_id=?) WHERE id=?",
            (data["doctor_id"], data["doctor_id"]))
    return jsonify({"ok": True})

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "service": "MediRural", "version": "1.0.0"})

# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    print("\n🏥  MediRural démarré sur http://localhost:5000")
    print("    Patients : marie@test.com / test123")
    print("    Médecins : kone@test.com  / test123\n")
    app.run(debug=True, port=5000)

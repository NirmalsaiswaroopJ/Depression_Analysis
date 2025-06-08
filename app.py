from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import base64
import cv2
import numpy as np
import os
import json
import mysql.connector
from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

# Try to import DeepFace, fallback to mock analysis if not available
try:
    from deepface import DeepFace
    DEEPFACE_AVAILABLE = True
except ImportError:
    DEEPFACE_AVAILABLE = False
    print("Warning: DeepFace not available. Using mock analysis.")

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_in_production'

# MySQL Database configuration
def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="Pandu@7463",
        database="sai_project",
        auth_plugin='mysql_native_password'
    )

# Database initialization
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Users table (patients and doctors)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'patient',
            full_name VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Assessments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            dominant_emotion VARCHAR(50),
            emotion_scores TEXT,
            depression_severity VARCHAR(50),
            depression_score FLOAT,
            image_quality VARCHAR(50),
            recommendations TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Doctor-Patient relationships
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_patients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            doctor_id INT NOT NULL,
            patient_id INT NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (doctor_id) REFERENCES users (id),
            FOREIGN KEY (patient_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin doctor
    cursor.execute('SELECT * FROM users WHERE username = %s', ('admin',))
    if not cursor.fetchone():
        admin_hash = generate_password_hash('admin123')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, full_name)
            VALUES (%s, %s, %s, %s, %s)
        ''', ('admin', 'admin@hospital.com', admin_hash, 'doctor', 'Dr. Admin'))
    
    conn.commit()
    conn.close()

# Store the last analysis result
last_analysis = None
last_report_path = "mood_report.txt"

def preprocess_uneven_image(img):
    """Preprocess uneven or poor quality images"""
    try:
        # Convert to grayscale for analysis
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Apply histogram equalization to improve contrast
        equalized = cv2.equalizeHist(gray)
        
        # Apply Gaussian blur to reduce noise
        blurred = cv2.GaussianBlur(equalized, (3, 3), 0)
        
        # Convert back to BGR for DeepFace
        processed = cv2.cvtColor(blurred, cv2.COLOR_GRAY2BGR)
        
        # Resize to standard size if needed
        height, width = processed.shape[:2]
        if width < 224 or height < 224:
            processed = cv2.resize(processed, (224, 224))
        
        return processed
    except Exception as e:
        print(f"Error preprocessing image: {e}")
        return img

def assess_image_quality(img):
    """Assess the quality of the input image"""
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Calculate sharpness using Laplacian variance
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Calculate brightness
        brightness = np.mean(gray)
        
        # Determine quality
        if laplacian_var > 100 and 50 < brightness < 200:
            return "Good"
        elif laplacian_var > 50 and 30 < brightness < 230:
            return "Fair"
        else:
            return "Poor"
    except:
        return "Unknown"

def calculate_depression_severity(emotion_scores):
    """Calculate depression severity based on emotion analysis"""
    try:
        # Depression indicators with weights
        depression_indicators = {
            'sad': 0.4,
            'angry': 0.2,
            'fear': 0.15,
            'disgust': 0.1,
            'neutral': 0.1,
            'surprise': -0.05,
            'happy': -0.3
        }
        
        severity_score = 0
        for emotion, score in emotion_scores.items():
            if emotion in depression_indicators:
                severity_score += (score / 100.0) * depression_indicators[emotion]
        
        # Normalize to 0-100 scale
        severity_score = max(0, min(100, severity_score * 100))
        
        # Classify severity
        if severity_score < 20:
            return "Minimal/None", severity_score
        elif severity_score < 40:
            return "Mild", severity_score
        elif severity_score < 60:
            return "Moderate", severity_score
        elif severity_score < 80:
            return "Moderately Severe", severity_score
        else:
            return "Severe", severity_score
    except:
        return "Unknown", 0

def mock_emotion_analysis():
    """Mock emotion analysis when DeepFace is not available"""
    import random
    emotions = ['happy', 'sad', 'angry', 'surprise', 'fear', 'disgust', 'neutral']
    
    # Simulate varying depression levels
    depression_bias = random.choice([0.1, 0.3, 0.5, 0.7])
    
    emotion_scores = {}
    if depression_bias > 0.5:
        # Simulate depressed state
        emotion_scores = {
            'sad': random.uniform(40, 70),
            'angry': random.uniform(10, 30),
            'fear': random.uniform(5, 20),
            'neutral': random.uniform(10, 25),
            'happy': random.uniform(1, 10),
            'surprise': random.uniform(1, 8),
            'disgust': random.uniform(2, 12)
        }
        dominant = 'sad'
    else:
        # Simulate normal state
        dominant = random.choice(emotions)
        emotion_scores = {}
        remaining = 100.0
        for emotion in emotions:
            if emotion == dominant:
                score = random.uniform(30, 60)
            else:
                score = random.uniform(1, remaining/len(emotions))
            emotion_scores[emotion] = score
            remaining -= score
    
    # Normalize to 100%
    total = sum(emotion_scores.values())
    emotion_scores = {k: round(v/total * 100, 2) for k, v in emotion_scores.items()}
    
    return {
        'dominant_emotion': dominant,
        'emotion': emotion_scores
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        
        if user['role'] == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('login_page'))

@app.route('/auth/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    full_name = request.form['full_name']
    role = request.form.get('role', 'patient')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, full_name)
            VALUES (%s, %s, %s, %s, %s)
        ''', (username, email, password_hash, role, full_name))
        conn.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login_page'))
    except mysql.connector.IntegrityError:
        flash('Username or email already exists')
        return redirect(url_for('register_page'))
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user_id' not in session or session['role'] != 'patient':
        return redirect(url_for('login_page'))
    
    # Get patient's assessment history
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT * FROM assessments WHERE user_id = %s ORDER BY created_at DESC LIMIT 10
    ''', (session['user_id'],))
    assessments = cursor.fetchall()
    conn.close()
    
    return render_template('patient_dashboard.html', assessments=assessments)

@app.route('/doctor/dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get all patients and their latest assessments
    cursor.execute('''
        SELECT u.id, u.full_name, u.email, u.created_at,
               a.depression_severity, a.depression_score, a.created_at as last_assessment
        FROM users u
        LEFT JOIN assessments a ON u.id = a.user_id
        WHERE u.role = 'patient'
        AND (a.id IS NULL OR a.id = (
            SELECT MAX(id) FROM assessments WHERE user_id = u.id
        ))
        ORDER BY a.created_at DESC
    ''')
    patients = cursor.fetchall()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "patient"')
    total_patients = cursor.fetchone()['COUNT(*)']
    
    cursor.execute('SELECT COUNT(*) FROM assessments WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)')
    recent_assessments = cursor.fetchone()['COUNT(*)']
    
    cursor.execute('''
        SELECT depression_severity, COUNT(*) 
        FROM assessments 
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY depression_severity
    ''')
    severity_stats = cursor.fetchall()
    
    conn.close()
    
    return render_template('doctor_dashboard.html', 
                         patients=patients, 
                         total_patients=total_patients,
                         recent_assessments=recent_assessments,
                         severity_stats=severity_stats)

@app.route('/start')
def start():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('start.html')

@app.route('/capture', methods=['POST'])
def capture():
    global last_analysis
    
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Please login first'})
    
    try:
        data = request.json
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'status': 'error', 'message': 'No image data received'})
        
        # Remove the data URL prefix
        if 'data:image/png;base64,' in image_data:
            image_data = image_data.replace('data:image/png;base64,', '')
        
        # Decode image
        img_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img_np is None:
            return jsonify({'status': 'error', 'message': 'Failed to decode image'})
        
        # Assess image quality
        image_quality = assess_image_quality(img_np)
        
        # Preprocess uneven images
        processed_img = preprocess_uneven_image(img_np)
        
        # Save processed image for reference
        cv2.imwrite('captured_image.png', processed_img)
        
        # Analyze mood
        if DEEPFACE_AVAILABLE:
            try:
                analysis = DeepFace.analyze(processed_img, actions=['emotion'], enforce_detection=False)
                if isinstance(analysis, list):
                    analysis = analysis[0]
                
                # Convert numpy values to native Python types for JSON serialization
                if 'emotion' in analysis:
                    analysis['emotion'] = {k: float(v) for k, v in analysis['emotion'].items()}
            except Exception as e:
                print(f"DeepFace analysis failed: {e}")
                analysis = mock_emotion_analysis()
        else:
            analysis = mock_emotion_analysis()
        
        # Calculate depression severity
        depression_severity, depression_score = calculate_depression_severity(analysis['emotion'])
        
        # Store analysis globally - ensure all values are JSON serializable
        last_analysis = {
            'dominant_emotion': analysis['dominant_emotion'],
            'emotion': analysis['emotion'],  # Already converted
            'depression_severity': depression_severity,
            'depression_score': float(depression_score),  # Ensure native float
            'image_quality': image_quality
        }
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO assessments (user_id, dominant_emotion, emotion_scores, 
                                   depression_severity, depression_score, image_quality, recommendations)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (
            session['user_id'],
            analysis['dominant_emotion'],
            json.dumps(analysis['emotion']),  # Now safe to serialize
            depression_severity,
            float(depression_score),  # Ensure native float
            image_quality,
            generate_recommendations(depression_severity, analysis['dominant_emotion'])
        ))
        conn.commit()
        conn.close()
        
        # Generate report
        generate_report(last_analysis)
        
        return jsonify({
            'status': 'success', 
            'mood': analysis['dominant_emotion'],
            'analysis': {
                'dominant_emotion': analysis['dominant_emotion'],
                'emotion_scores': analysis['emotion'],
                'depression_severity': depression_severity,
                'depression_score': float(depression_score)
            }
        })
        
    except Exception as e:
        print(f"Error in capture: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

def generate_recommendations(severity, dominant_emotion):
    """Generate recommendations based on depression severity"""
    recommendations = []
    
    if severity in ["Moderate", "Moderately Severe", "Severe"]:
        recommendations.extend([
            "Consider consulting with a mental health professional",
            "Practice mindfulness and meditation techniques",
            "Maintain regular sleep schedule",
            "Engage in regular physical exercise",
            "Stay connected with friends and family"
        ])
        
        if severity == "Severe":
            recommendations.insert(0, "Seek immediate professional help - consider emergency services if having suicidal thoughts")
    else:
        recommendations.extend([
            "Continue maintaining good mental health habits",
            "Monitor mood changes over time",
            "Practice stress management techniques"
        ])
    
    return json.dumps(recommendations)

def generate_report(analysis):
    """Generate a detailed depression assessment report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(last_report_path, 'w') as f:
        f.write("DEPRESSION SEVERITY ASSESSMENT REPORT\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Assessment Date: {timestamp}\n")
        f.write(f"Patient: {session.get('full_name', 'Unknown')}\n")
        f.write(f"Image Quality: {analysis.get('image_quality', 'Unknown')}\n\n")
        
        f.write(f"DEPRESSION SEVERITY: {analysis['depression_severity'].upper()}\n")
        f.write(f"Depression Score: {analysis['depression_score']:.2f}/100\n\n")
        
        f.write(f"DOMINANT EMOTION: {analysis['dominant_emotion'].upper()}\n\n")
        
        f.write("DETAILED EMOTION ANALYSIS:\n")
        f.write("-" * 30 + "\n")
        
        sorted_emotions = sorted(analysis['emotion'].items(), key=lambda x: x[1], reverse=True)
        
        for emotion, score in sorted_emotions:
            f.write(f"{emotion.capitalize():<12}: {score:>6.2f}%\n")
        
        f.write(f"\n{'=' * 50}\n")
        
        # Add clinical interpretation
        interpretations = {
            "Minimal/None": "No significant signs of depression detected. Continue monitoring.",
            "Mild": "Mild depressive symptoms detected. Consider lifestyle changes and monitoring.",
            "Moderate": "Moderate depression symptoms. Professional consultation recommended.",
            "Moderately Severe": "Significant depression symptoms. Professional help strongly recommended.",
            "Severe": "Severe depression indicators. Immediate professional intervention needed."
        }
        
        interpretation = interpretations.get(analysis['depression_severity'], 
                                           "Depression assessment completed.")
        
        f.write(f"\nCLINICAL INTERPRETATION:\n{interpretation}\n\n")
        
        f.write("RECOMMENDATIONS:\n")
        f.write("- Regular monitoring of mental health status\n")
        f.write("- Maintain consistent sleep and exercise routines\n")
        if analysis['depression_score'] > 40:
            f.write("- Consider professional counseling or therapy\n")
            f.write("- Discuss with healthcare provider about treatment options\n")
        f.write("- Stay connected with support system\n")
        f.write("- Practice stress management techniques\n\n")
        
        f.write("IMPORTANT NOTICE:\n")
        f.write("This assessment is a screening tool only and should not replace\n")
        f.write("professional medical diagnosis. If you're experiencing thoughts of\n")
        f.write("self-harm or suicide, please seek immediate emergency help.\n")

@app.route('/result')
def result():
    global last_analysis
    
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    if last_analysis is None:
        return redirect(url_for('patient_dashboard'))
    
    report_content = ""
    if os.path.exists(last_report_path):
        with open(last_report_path, 'r') as f:
            report_content = f.read()
    
    return render_template('result.html', 
                         mood=last_analysis['dominant_emotion'],
                         analysis=last_analysis,
                         report_content=report_content)

@app.route('/download_report')
def download_report():
    if os.path.exists(last_report_path):
        return send_file(last_report_path, 
                        as_attachment=True, 
                        download_name=f"depression_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    else:
        return "No report available", 404

@app.route('/patient/<int:patient_id>')
def patient_detail(patient_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get patient info
    cursor.execute('SELECT * FROM users WHERE id = %s AND role = "patient"', (patient_id,))
    patient = cursor.fetchone()
    
    if not patient:
        flash('Patient not found')
        return redirect(url_for('doctor_dashboard'))
    
    # Get patient's assessment history
    cursor.execute('''
        SELECT *, 
               JSON_UNQUOTE(emotion_scores) AS emotion_scores_json
        FROM assessments 
        WHERE user_id = %s 
        ORDER BY created_at DESC
    ''', (patient_id,))
    assessments = cursor.fetchall()
    
    # Convert emotion_scores to Python dict if it's a string
    for assessment in assessments:
        if isinstance(assessment['emotion_scores'], str):
            try:
                assessment['emotion_scores'] = json.loads(assessment['emotion_scores'])
            except json.JSONDecodeError:
                assessment['emotion_scores'] = {}
    
    conn.close()
    
    return render_template('patient_detail.html', 
                         patient=patient, 
                         assessments=assessments,
                         now=datetime.now())

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
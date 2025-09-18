from flask import Flask, render_template, request, jsonify
from google import genai
import sqlite3
import os
from datetime import datetime, timedelta
import json
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Configure Gemini API
GEMINI_API_KEY = "AIzaSyDh_q12etYVVvBmqqqZzfO5aGiWZ2Z-lB4"  # Replace with your actual API key
client = genai.Client(api_key=GEMINI_API_KEY)

# Database initialization
def init_db():
    conn = sqlite3.connect('safety_reports.db')
    c = conn.cursor()
    
    # Create incidents table
    c.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            description TEXT NOT NULL,
            date_reported TEXT NOT NULL,
            time_reported TEXT NOT NULL,
            severity INTEGER NOT NULL,
            reporter_contact TEXT,
            latitude REAL,
            longitude REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create chat sessions table for conversation history with session tracking
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            session_type TEXT NOT NULL,
            user_message TEXT NOT NULL,
            bot_response TEXT NOT NULL,
            question_count INTEGER DEFAULT 0,
            collected_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def get_db_connection():
    conn = sqlite3.connect('safety_reports.db')
    conn.row_factory = sqlite3.Row
    return conn

def calculate_incident_severity(incident_type, description):
    """Calculate incident severity based on type and description keywords"""
    severity = 1  # Start with lowest severity
    description_lower = description.lower()
    
    # Base severity by incident type
    type_severity = {
        "General Incident": 2,
        "Theft": 3,
        "Accident": 3,
        "Harassment": 4,
        "Assault": 5
    }
    
    severity = type_severity.get(incident_type, 2)
    
    # Increase severity based on description keywords
    high_severity_keywords = {
        # Violence indicators (increase by 2)
        "murder": 2, "killed": 2, "stabbed": 2, "shot": 2, "gun": 2, "knife": 2,
        "beaten": 2, "attacked": 2, "violence": 2, "blood": 2, "injured": 2,
        "death": 2, "die": 2, "dead": 2, "fatal": 2,
        
        # Weapon indicators (increase by 1-2)
        "weapon": 1, "armed": 2, "pistol": 2, "rifle": 2, "blade": 1, "sword": 1,
        "hammer": 1, "bat": 1, "stick": 1,
        
        # Severity modifiers (increase by 1)
        "serious": 1, "severe": 1, "multiple": 1, "gang": 1, "group": 1,
        "repeated": 1, "again": 1, "emergency": 1, "hospital": 1, "ambulance": 1,
        "police": 1, "911": 1, "urgent": 1, "critical": 1, "dangerous": 1,
        
        # Sexual crimes (increase by 2)
        "rape": 2, "sexual": 2, "molest": 2, "inappropriately": 1, "touched": 1,
        
        # Property damage severity
        "destroyed": 1, "vandalized": 1, "broken": 1, "damaged": 1, "fire": 1,
        "explosion": 1, "bomb": 2,
        
        # Financial impact
        "expensive": 1, "valuable": 1, "money": 1, "cash": 1, "wallet": 1,
        "purse": 1, "jewelry": 1, "phone": 1, "laptop": 1,
        
        # Threat levels
        "threat": 1, "threatened": 1, "intimidated": 1, "scared": 1, "fear": 1,
        
        # Drug-related
        "drugs": 1, "cocaine": 1, "heroin": 1, "meth": 1, "dealer": 1,
        
        # Time indicators (night incidents are more severe)
        "night": 1, "midnight": 1, "dark": 1, "late": 1,
        
        # Location severity modifiers
        "alley": 1, "isolated": 1, "alone": 1, "empty": 1, "deserted": 1
    }
    
    # Check for severity-increasing keywords
    for keyword, increase in high_severity_keywords.items():
        if keyword in description_lower:
            severity += increase
    
    # Additional context-based increases
    if "multiple" in description_lower and any(word in description_lower for word in ["people", "persons", "individuals"]):
        severity += 1  # Multiple perpetrators
        
    if any(word in description_lower for word in ["child", "minor", "kid", "teenager"]):
        severity += 1  # Crimes involving minors are more severe
        
    if any(word in description_lower for word in ["elderly", "old", "senior"]):
        severity += 1  # Crimes against elderly are more severe
    
    # Ensure severity stays within 1-5 range
    severity = max(1, min(5, severity))
    
    return severity

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report')
def report_incident():
    return render_template('report.html')

@app.route('/check_safety')
def check_safety():
    return render_template('check_safety.html')

@app.route('/api/chat/report', methods=['POST'])
def chat_report():
    try:
        data = request.json
        user_message = data.get('message', '')
        session_id = data.get('session_id', 'default_session')
        
        # Get conversation history for this session
        conn = get_db_connection()
        chat_history = conn.execute('''
            SELECT user_message, bot_response, question_count, collected_data 
            FROM chat_sessions 
            WHERE session_id = ? AND session_type = 'report'
            ORDER BY created_at DESC
            LIMIT 1
        ''', (session_id,)).fetchone()
        
        # Parse existing collected data
        collected_info = {}
        question_count = 0
        
        if chat_history:
            question_count = chat_history['question_count'] or 0
            if chat_history['collected_data']:
                try:
                    collected_info = json.loads(chat_history['collected_data'])
                except:
                    collected_info = {}
        
        # Define the 3 restricted questions in order
        required_questions = [
            "Where did the incident occur? Please provide the specific location or address.",
            "What time did this incident happen? Please provide both the date and time.",
            "What exactly happened? Please describe the incident in detail."
        ]
        
        # Process user response based on current question
        if question_count == 0:
            # First interaction - ask where
            bot_response = f"I'll help you report this incident. I need to ask you 3 specific questions. {required_questions[0]}"
            question_count = 1
            
        elif question_count == 1:
            # Store location info
            collected_info["location"] = user_message
            collected_info["where"] = user_message
            bot_response = required_questions[1]
            question_count = 2
            
        elif question_count == 2:
            # Store time info and try to parse it
            collected_info["when"] = user_message
            
            # Time and date parsing - can be enhanced
            now = datetime.now()
            collected_info["date_reported"] = now.strftime("%Y-%m-%d")
            collected_info["time_reported"] = now.strftime("%H:%M")
            
            # Simple time extraction
            time_match = re.search(r'(\d{1,2}):(\d{2})\s*(am|pm)?', user_message.lower())
            if time_match:
                collected_info["time_reported"] = time_match.group(0)
            # Parse "today" or "yesterday"
            if "yesterday" in user_message.lower():
                collected_info["date_reported"] = (now - timedelta(days=1)).strftime("%Y-%m-%d")
            elif "today" in user_message.lower():
                collected_info["date_reported"] = now.strftime("%Y-%m-%d")
                
            bot_response = required_questions[2]
            question_count = 3
            
        elif question_count == 3:
            # Store description and classify incident
            collected_info["description"] = user_message
            collected_info["what"] = user_message
            
            # Enhanced type classification with more keywords
            incident_type = "General Incident"
            description_lower = user_message.lower()
            
            # Theft-related keywords
            if any(word in description_lower for word in ["theft", "stolen", "robbed", "robbery", "pickpocket", "snatched", "grabbed", "took"]):
                incident_type = "Theft"
            # Accident-related keywords    
            elif any(word in description_lower for word in ["accident", "crash", "collision", "hit", "fell", "slip", "trip", "injured"]):
                incident_type = "Accident"
            # Harassment-related keywords
            elif any(word in description_lower for word in ["harassment", "harassed", "inappropriate", "followed", "stalked", "bothered", "catcalled"]):
                incident_type = "Harassment"
            # Assault-related keywords (most severe)
            elif any(word in description_lower for word in ["assault", "attacked", "violence", "beaten", "hit", "punched", "kicked", "stabbed", "shot"]):
                incident_type = "Assault"
            # Vandalism
            elif any(word in description_lower for word in ["vandalism", "damaged", "broken", "destroyed", "graffiti", "vandalized"]):
                incident_type = "Vandalism"
            # Fraud
            elif any(word in description_lower for word in ["fraud", "scam", "cheated", "fake", "counterfeit"]):
                incident_type = "Fraud"
            
            collected_info["incident_type"] = incident_type
            
            # Calculate dynamic severity based on incident content
            calculated_severity = calculate_incident_severity(incident_type, user_message)
            collected_info["severity"] = calculated_severity
            
            try:
                conn.execute('''
                    INSERT INTO incidents (location, incident_type, description, 
                                         date_reported, time_reported, severity, reporter_contact)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    collected_info.get("location", "Unknown"),
                    collected_info.get("incident_type", "General Incident"),
                    collected_info.get("description", "No description"),
                    collected_info.get("date_reported"),
                    collected_info.get("time_reported"),
                    collected_info.get("severity", 3),
                    None
                ))
                conn.commit()
                
                # Enhanced confirmation message with severity info
                severity_labels = {1: "Very Low", 2: "Low", 3: "Medium", 4: "High", 5: "Very High"}
                severity_label = severity_labels.get(calculated_severity, "Medium")
                
                bot_response = f"Thank you! Your incident report has been successfully submitted to our safety database.\n\nIncident Summary:\n- Type: {incident_type}\n- Severity Level: {calculated_severity}/5 ({severity_label})\n- Location: {collected_info.get('location', 'Unknown')}\n\nThis information will help other community members make informed decisions about safety in your area."
                question_count = 0
                collected_info = {}
            except Exception as e:
                bot_response = f"There was an error submitting your report: {str(e)}. Please try again."
        
        # Store chat session
        conn.execute('''
            INSERT INTO chat_sessions (session_id, session_type, user_message, bot_response, question_count, collected_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, 'report', user_message, bot_response, question_count, json.dumps(collected_info)))
        conn.commit()
        conn.close()
        
        return jsonify({
            'response': bot_response,
            'question_count': question_count,
            'collected_info': collected_info
        })
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

def extract_location_from_message(message):
    """Enhanced location extraction function"""
    # Common location patterns
    location_patterns = [
        r'(?:in|at|near|around)\s+([A-Za-z\s,]+?)(?:\s+(?:is|was|area|street|road|avenue))',
        r'([A-Za-z\s,]+?)(?:\s+(?:area|street|road|avenue|mall|park|station))',
        r'(?:location|place|area):\s*([A-Za-z\s,]+)',
        r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b'  # Capitalized words (likely place names)
    ]
    
    locations = []
    for pattern in location_patterns:
        matches = re.findall(pattern, message, re.IGNORECASE)
        locations.extend(matches)
    
    # Clean and deduplicate
    cleaned_locations = []
    for loc in locations:
        cleaned = loc.strip().title()
        if len(cleaned) > 2 and cleaned not in cleaned_locations:
            cleaned_locations.append(cleaned)
    
    return cleaned_locations[:5]  # Return top 5 potential locations

@app.route('/api/chat/safety', methods=['POST'])
def chat_safety():
    try:
        data = request.json
        user_message = data.get('message', '')
        session_id = data.get('session_id', f'safety_{datetime.now().timestamp()}')
        
        # Get relevant incident data from database
        conn = get_db_connection()
        
        # Enhanced location extraction
        potential_locations = extract_location_from_message(user_message)
        
        incidents = []
        location_summary = ""
        
        if potential_locations:
            # Search for incidents in mentioned locations
            location_conditions = []
            params = []
            for location in potential_locations:
                location_conditions.append("location LIKE ?")
                params.append(f'%{location}%')
            
            if location_conditions:
                location_query = ' OR '.join(location_conditions)
                incidents = conn.execute(f'''
                    SELECT * FROM incidents 
                    WHERE {location_query}
                    ORDER BY created_at DESC, severity DESC
                    LIMIT 15
                ''', params).fetchall()
                
                location_summary = f"Searching for incidents in: {', '.join(potential_locations)}"
        
        # If no specific location found or no incidents, get recent general incidents
        if not incidents:
            incidents = conn.execute('''
                SELECT * FROM incidents 
                ORDER BY created_at DESC, severity DESC
                LIMIT 10
            ''').fetchall()
            location_summary = "No specific location mentioned. Showing recent community incidents."
        
        # Build comprehensive incident data summary
        incident_data = ""
        severity_stats = {"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
        incident_types = {}
        recent_incidents = []
        
        if incidents:
            incident_data = f"=== INCIDENT DATABASE ANALYSIS ===\n"
            incident_data += f"{location_summary}\n"
            incident_data += f"Total incidents found: {len(incidents)}\n\n"
            
            for incident in incidents:
                # Count severity levels
                severity_stats[str(incident['severity'])] += 1
                
                # Count incident types
                incident_type = incident['incident_type']
                incident_types[incident_type] = incident_types.get(incident_type, 0) + 1
                
                # Add to recent incidents list
                recent_incidents.append({
                    'type': incident['incident_type'],
                    'location': incident['location'],
                    'date': incident['date_reported'],
                    'time': incident['time_reported'],
                    'severity': incident['severity'],
                    'description': incident['description'][:100] + "..." if len(incident['description']) > 100 else incident['description']
                })
            
            # Add statistics
            incident_data += "SEVERITY BREAKDOWN:\n"
            for sev, count in severity_stats.items():
                if count > 0:
                    severity_label = {
                        "1": "Very Low", "2": "Low", "3": "Medium", 
                        "4": "High", "5": "Very High"
                    }[sev]
                    incident_data += f"- Severity {sev} ({severity_label}): {count} incidents\n"
            
            incident_data += "\nINCIDENT TYPES:\n"
            for inc_type, count in incident_types.items():
                incident_data += f"- {inc_type}: {count} incidents\n"
            
            incident_data += "\nRECENT INCIDENT DETAILS:\n"
            for i, incident in enumerate(recent_incidents[:8]):  # Show top 8 most recent/severe
                incident_data += f"{i+1}. {incident['type']} in {incident['location']}\n"
                incident_data += f"   Date: {incident['date']} at {incident['time']}\n"
                incident_data += f"   Severity: {incident['severity']}/5\n"
                incident_data += f"   Description: {incident['description']}\n\n"
        else:
            incident_data = "=== INCIDENT DATABASE ANALYSIS ===\n"
            incident_data += "No incidents found in our database for the specified criteria.\n"
            incident_data += "This could mean the area is generally safe, but users should still exercise normal caution.\n"
        
        # Get chat history for context
        chat_history = conn.execute('''
            SELECT user_message, bot_response FROM chat_sessions 
            WHERE session_id = ? AND session_type = 'safety_check'
            ORDER BY created_at DESC
            LIMIT 3
        ''', (session_id,)).fetchall()
        
        conversation_context = ""
        if chat_history:
            conversation_context = "Previous conversation:\n"
            for chat in reversed(chat_history):
                conversation_context += f"User: {chat['user_message']}\n"
                conversation_context += f"Assistant: {chat['bot_response'][:200]}...\n\n"
        
        # Enhanced system prompt that forces use of database data
        system_prompt = f"""You are a Community Safety AI Assistant with access to a real-time incident database. Give me in neat strutured way without any bold words.

CRITICAL INSTRUCTIONS:
1. You MUST base your safety assessment primarily on the incident database data provided below
2. You MUST reference specific incidents from the database when relevant
3. You MUST provide data-driven safety recommendations
4. If no incidents are found, state this clearly and explain what this means for safety

{incident_data}

{conversation_context}

RESPONSE REQUIREMENTS:
- Start with a clear safety assessment based on the DATABASE DATA
- Quote specific incidents with details (location, date, type, severity)
- Provide statistical analysis from the database
- Give practical, data-informed safety advice
- Mention if patterns exist (time of day, incident types, locations)
- Encourage reporting new incidents to keep the database current
- Keep responses conversational but fact-based

SEVERITY LEVEL INTERPRETATION:
- 0 incidents = Generally safe area, maintain normal precautions
- 1-2 incidents = Low concern, be aware of incident types
- 3-5 incidents = Moderate concern, take specific precautions
- 6+ incidents = Higher concern, consider alternative routes/times

SEVERITY MEANINGS:
- Level 1 (Very Low): Minor issues, minimal impact
- Level 2 (Low): Minor theft, property issues
- Level 3 (Medium): Theft, accidents, harassment
- Level 4 (High): Assault, weapons, serious harm
- Level 5 (Very High): Life-threatening, extreme violence

Remember: Your primary role is to analyze and communicate the DATABASE INFORMATION effectively."""
        
        # Generate response using Gemini with enhanced context
        full_prompt = f"{system_prompt}\n\nUser Question: {user_message}\n\nProvide a comprehensive safety analysis based on the incident database data above."
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=full_prompt
        )
        
        bot_response = response.text
        
        # Store chat session with database context
        conn.execute('''
            INSERT INTO chat_sessions (session_id, session_type, user_message, bot_response, collected_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, 'safety_check', user_message, bot_response, json.dumps({
            'incidents_found': len(incidents),
            'locations_searched': potential_locations,
            'incident_types': list(incident_types.keys()) if incident_types else [],
            'severity_distribution': severity_stats
        })))
        conn.commit()
        conn.close()
        
        return jsonify({
            'response': bot_response,
            'incidents_analyzed': len(incidents),
            'locations_searched': potential_locations,
            'database_stats': {
                'total_incidents': len(incidents),
                'incident_types': incident_types,
                'severity_distribution': severity_stats
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/api/incidents')
def get_incidents():
    try:
        conn = get_db_connection()
        incidents = conn.execute('''
            SELECT * FROM incidents 
            ORDER BY created_at DESC 
            LIMIT 50
        ''').fetchall()
        conn.close()
        
        incidents_list = []
        for incident in incidents:
            incidents_list.append({
                'id': incident['id'],
                'location': incident['location'],
                'incident_type': incident['incident_type'],
                'description': incident['description'],
                'date_reported': incident['date_reported'],
                'time_reported': incident['time_reported'],
                'severity': incident['severity'],
                'created_at': incident['created_at']
            })
        
        return jsonify(incidents_list)
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/api/stats')
def get_stats():
    """New endpoint to get database statistics"""
    try:
        conn = get_db_connection()
        
        # Get total incidents
        total_incidents = conn.execute('SELECT COUNT(*) as count FROM incidents').fetchone()['count']
        
        # Get incidents by type
        incident_types = conn.execute('''
            SELECT incident_type, COUNT(*) as count 
            FROM incidents 
            GROUP BY incident_type 
            ORDER BY count DESC
        ''').fetchall()
        
        # Get incidents by severity
        severity_stats = conn.execute('''
            SELECT severity, COUNT(*) as count 
            FROM incidents 
            GROUP BY severity 
            ORDER BY severity
        ''').fetchall()
        
        # Get recent incidents (last 7 days)
        seven_days_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        recent_incidents = conn.execute('''
            SELECT COUNT(*) as count 
            FROM incidents 
            WHERE date_reported >= ?
        ''', (seven_days_ago,)).fetchone()['count']
        
        # Get average severity
        avg_severity = conn.execute('SELECT AVG(severity) as avg FROM incidents').fetchone()['avg']
        avg_severity = round(avg_severity, 2) if avg_severity else 0
        
        conn.close()
        
        return jsonify({
            'total_incidents': total_incidents,
            'recent_incidents': recent_incidents,
            'average_severity': avg_severity,
            'incident_types': [{'type': row['incident_type'], 'count': row['count']} for row in incident_types],
            'severity_distribution': [{'severity': row['severity'], 'count': row['count']} for row in severity_stats]
        })
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)


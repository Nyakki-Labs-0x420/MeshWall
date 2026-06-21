import asyncio
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, current_app
from meshwall.ai.client import OllamaClient
from meshwall.models import ChatMessage, FeedBlock, BlockedIP
from meshwall.webapp.extensions import db

chat_bp = Blueprint('chat', __name__)

MODEL = 'artifish/llama3.2-uncensored:latest'

# ----------------------------------------------------------------------
# Data gathering
# ----------------------------------------------------------------------
def _get_stats():import asyncio
from flask import Blueprint, render_template, request, jsonify, current_app
from meshwall.ai.client import OllamaClient
from meshwall.models import ChatMessage                
from meshwall.webapp.extensions import db

chat_bp = Blueprint('chat', __name__)

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for MeshWall, an intrusion detection system. Answer questions based on the conversation history and any provided data. Be concise and technical."""

@chat_bp.route('/')
def chat():
    messages = ChatMessage.query.order_by(ChatMessage.created_at).all()
    encryptor = current_app.config['encryptor']
    history = [{'role': m.role, 'content': encryptor.decrypt(m.content_encrypted)} for m in messages]
    return render_template('chat.html', history=history)

@chat_bp.route('/send', methods=['POST'])
def send():
    user_msg = request.json.get('message', '')
    if not user_msg:
        return jsonify({'error': 'Empty message'}), 400

    encryptor = current_app.config['encryptor']
    db.session.add(ChatMessage(role='user', content_encrypted=encryptor.encrypt(user_msg)))
    db.session.commit()

    messages = ChatMessage.query.order_by(ChatMessage.created_at).all()
    messages_for_ai = [{"role": "system", "content": SYSTEM_PROMPT}] + [
        {'role': m.role, 'content': encryptor.decrypt(m.content_encrypted)} for m in messages
    ]

    async def get_response():
        client = OllamaClient(model='phi3:mini')
        async with client:
            return await client.chat(messages_for_ai)

    try:
        assistant_msg = asyncio.run(get_response())
    except Exception as e:
        assistant_msg = f"Error communicating with AI: {str(e)}"

    db.session.add(ChatMessage(role='assistant', content_encrypted=encryptor.encrypt(assistant_msg)))
    db.session.commit()

    return jsonify({'message': assistant_msg})
    total_feed = db.session.query(FeedBlock).count()
    cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_scans = BlockedIP.query.filter(
        BlockedIP.blocked_at >= cutoff
    ).all()

    # Countries aggregation
    countries = {}
    for ip in recent_scans:
        c = ip.geo_country or 'Unknown'
        countries[c] = countries.get(c, 0) + 1
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]

    # Last 10 distinct attacker IPs with geo details
    distinct_ips = []
    seen = set()
    for ip in recent_scans:
        if ip.ip not in seen:
            seen.add(ip.ip)
            distinct_ips.append({
                'ip': ip.ip,
                'country': ip.geo_country or 'Unknown',
                'city': ip.geo_city or 'Unknown',
                'reason': ip.reason or 'unknown',
                'time': ip.blocked_at.strftime('%Y-%m-%d %H:%M') if ip.blocked_at else 'unknown'
            })
        if len(distinct_ips) >= 10:
            break

    return {
        'total_feed': total_feed,
        'recent_scan_count': len(recent_scans),
        'top_countries': top_countries,
        'distinct_ips': distinct_ips
    }

def _build_facts() -> str:
    """Return a plain-text fact sheet with threat intelligence details."""
    stats = _get_stats()
    top_str = ', '.join(f'{c} ({n})' for c, n in stats['top_countries']) if stats['top_countries'] else 'none'

    lines = [
        f"Total blocked IPs from threat feeds: {stats['total_feed']}",
        f"Scan events in the last 24 hours: {stats['recent_scan_count']}",
        f"Top attacking countries: {top_str}",
        "",
        "Recent attackers (IP, country, city, reason, time):"
    ]
    for ip in stats['distinct_ips']:
        lines.append(f"- {ip['ip']} | {ip['country']} | {ip['city']} | {ip['reason']} | {ip['time']}")

    return '\n'.join(lines)

# ----------------------------------------------------------------------
# Contextual AI call – includes recent chat history and detailed facts
# ----------------------------------------------------------------------
async def _call_ai(user_message: str) -> str:
    facts = _build_facts()

    # Retrieve the last 10 messages for context
    recent_msgs = ChatMessage.query.order_by(ChatMessage.created_at.desc()).limit(10).all()
    recent_msgs.reverse()
    encryptor = current_app.config['encryptor']
    history_text = ""
    for m in recent_msgs:
        role = "User" if m.role == "user" else "Assistant"
        content = encryptor.decrypt(m.content_encrypted)
        history_text += f"{role}: {content}\n"

    prompt = (
        f"Here is the current MeshWall threat intelligence:\n\n"
        f"{facts}\n\n"
        f"Recent conversation:\n{history_text}\n"
        f"User: {user_message}\n\n"
        f"Assistant:"
    )

    client = OllamaClient(model=MODEL)
    async with client:
        return await client.generate(prompt)

# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
@chat_bp.route('/')
def chat():
    messages = ChatMessage.query.order_by(ChatMessage.created_at).all()
    encryptor = current_app.config['encryptor']
    history = [{'role': m.role, 'content': encryptor.decrypt(m.content_encrypted)} for m in messages]
    return render_template('chat.html', history=history)

@chat_bp.route('/send', methods=['POST'])
def send():
    user_msg = request.json.get('message', '')
    if not user_msg:
        return jsonify({'error': 'Empty message'}), 400

    encryptor = current_app.config['encryptor']
    db.session.add(ChatMessage(role='user', content_encrypted=encryptor.encrypt(user_msg)))
    db.session.commit()

    # Always go through AI with contextual prompt
    try:
        ai_reply = asyncio.run(_call_ai(user_msg))
    except Exception:
        ai_reply = _build_facts()

    db.session.add(ChatMessage(role='assistant', content_encrypted=encryptor.encrypt(ai_reply)))
    db.session.commit()

    return jsonify({'message': ai_reply})

import asyncio
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
import requests
from flask import current_app


def chat_with_ai(ai_config, messages):
    provider = ai_config.provider
    model = ai_config.model
    system_prompt = ai_config.system_prompt
    full_messages = [{"role": "system", "content": system_prompt}] + messages

    try:
        if provider == 'openai':
            return _chat_openai(ai_config.api_key or current_app.config.get('OPENAI_API_KEY', ''),
                                model, full_messages)
        elif provider == 'gemini':
            return _chat_gemini(ai_config.api_key or current_app.config.get('GEMINI_API_KEY', ''),
                                model, full_messages)
        elif provider == 'ollama':
            return _chat_ollama(ai_config.ollama_url, model, full_messages,
                                api_key=ai_config.api_key or None)
        else:
            return {"error": f"Unknown provider: {provider}"}
    except Exception as e:
        return {"error": str(e)}


def test_ai_connection(provider, api_key, ollama_url, model):
    try:
        if provider == 'openai':
            return _test_openai(api_key, model)
        elif provider == 'gemini':
            return _test_gemini(api_key, model)
        elif provider == 'ollama':
            return _test_ollama(ollama_url, model, api_key)
        else:
            return {"success": False, "error": f"Unknown provider: {provider}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_ollama_models(ollama_url, api_key=None):
    try:
        url = f'{ollama_url.rstrip("/")}/api/tags'
        headers = {}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 401:
            return {"error": "Authentication failed – check API key"}
        if resp.status_code != 200:
            return {"error": f"Ollama unreachable (status {resp.status_code})"}
        data = resp.json()
        models = []
        for m in data.get('models', []):
            name = m.get('name', '')
            size_bytes = m.get('size', 0)
            size_gb = round(size_bytes / (1024**3), 1) if size_bytes else 0
            details = m.get('details', {})
            models.append({
                'name': name,
                'size': f"{size_gb} GB" if size_gb else '?',
                'family': details.get('family', ''),
                'parameters': details.get('parameter_size', ''),
                'quantization': details.get('quantization_level', ''),
            })
        return {"models": models}
    except requests.ConnectionError:
        return {"error": f"Ollama unreachable at {ollama_url}"}
    except Exception as e:
        return {"error": str(e)}


def _test_ollama(ollama_url, model, api_key=None):
    model_name = model or 'llama3'
    try:
        url = f'{ollama_url.rstrip("/")}/api/chat'
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        resp = requests.post(url, headers=headers,
            json={'model': model_name,
                  'messages': [{'role': 'user', 'content': 'Hi, reply with OK only'}],
                  'stream': False}, timeout=30)
        if resp.status_code == 200:
            return {"success": True, "message": f"Ollama connection OK (model: {model_name})"}
        elif resp.status_code == 401:
            return {"success": False, "error": "Authentication failed – check API key"}
        elif resp.status_code == 404:
            return {"success": False, "error": f"Model '{model_name}' not installed. Run: ollama pull {model_name}"}
        else:
            return {"success": False, "error": f"Status {resp.status_code}: {resp.text[:200]}"}
    except requests.ConnectionError:
        return {"success": False, "error": f"Ollama unreachable at {ollama_url}"}
    except requests.Timeout:
        return {"success": False, "error": "Timeout (model may be loading)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _test_gemini(api_key, model):
    if not api_key:
        return {"success": False, "error": "API key missing"}
    model_name = model or 'gemini-2.0-flash'
    try:
        resp = requests.post(
            f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}',
            headers={'Content-Type': 'application/json'},
            json={'contents': [{'role': 'user', 'parts': [{'text': 'Hi, reply with OK only'}]}]},
            timeout=15
        )
        if resp.status_code == 200:
            return {"success": True, "message": f"Gemini connection OK (model: {model_name})"}
        elif resp.status_code == 400:
            return {"success": False, "error": "Invalid API key or model"}
        else:
            return {"success": False, "error": f"Status {resp.status_code}: {resp.text[:200]}"}
    except requests.Timeout:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _test_openai(api_key, model):
    if not api_key:
        return {"success": False, "error": "API key missing"}
    try:
        resp = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={'model': model or 'gpt-4o-mini',
                  'messages': [{'role': 'user', 'content': 'Hi, reply with OK only'}],
                  'max_tokens': 5},
            timeout=15
        )
        if resp.status_code == 200:
            return {"success": True, "message": f"OpenAI connection OK (model: {model or 'gpt-4o-mini'})"}
        elif resp.status_code == 401:
            return {"success": False, "error": "Invalid API key"}
        elif resp.status_code == 404:
            return {"success": False, "error": f"Model '{model}' not found"}
        else:
            return {"success": False, "error": f"Status {resp.status_code}: {resp.text[:200]}"}
    except requests.Timeout:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _chat_openai(api_key, model, messages):
    if not api_key:
        return {"error": "OpenAI API key not configured. Please configure in the admin area."}
    resp = requests.post('https://api.openai.com/v1/chat/completions',
        headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
        json={'model': model or 'gpt-4o-mini', 'messages': messages,
              'max_tokens': 2048, 'temperature': 0.7}, timeout=60)
    if resp.status_code != 200:
        return {"error": f"OpenAI error {resp.status_code}: {resp.text[:200]}"}
    return {"content": resp.json()['choices'][0]['message']['content']}


def _chat_gemini(api_key, model, messages):
    if not api_key:
        return {"error": "Gemini API key not configured. Please configure in the admin area."}
    model_name = model or 'gemini-2.0-flash'
    contents = []
    system_text = ""
    for msg in messages:
        if msg['role'] == 'system':
            system_text = msg['content']
        else:
            role = 'user' if msg['role'] == 'user' else 'model'
            contents.append({'role': role, 'parts': [{'text': msg['content']}]})
    body = {'contents': contents}
    if system_text:
        body['systemInstruction'] = {'parts': [{'text': system_text}]}
    resp = requests.post(
        f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}',
        headers={'Content-Type': 'application/json'}, json=body, timeout=60)
    if resp.status_code != 200:
        return {"error": f"Gemini error {resp.status_code}: {resp.text[:200]}"}
    data = resp.json()
    try:
        return {"content": data['candidates'][0]['content']['parts'][0]['text']}
    except (KeyError, IndexError):
        return {"error": "Unexpected Gemini response"}


def _chat_ollama(base_url, model, messages, api_key=None):
    url = f'{base_url.rstrip("/")}/api/chat'
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    try:
        resp = requests.post(url, headers=headers,
                             json={'model': model or 'llama3', 'messages': messages,
                                   'stream': False}, timeout=120)
    except requests.ConnectionError:
        return {"error": f"Ollama unreachable at {base_url}. Please check in the admin area."}
    if resp.status_code == 401:
        return {"error": "Ollama authentication failed. Check API key in the admin area."}
    if resp.status_code != 200:
        return {"error": f"Ollama error {resp.status_code}: {resp.text[:200]}"}
    return {"content": resp.json().get('message', {}).get('content', 'No response')}
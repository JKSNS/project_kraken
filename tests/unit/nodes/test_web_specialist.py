"""Tests for kraken.nodes.web_specialist -- web technology detection."""
import pytest

from kraken.nodes.web_specialist import _detect_web_tech


class TestDetectWebTech:
    """Test deterministic web technology detection (no LLM calls).

    Note: _detect_web_tech checks challenge_files content_preview for framework
    detection, and the strings list only for server tech (nginx/apache/gunicorn).
    """

    def test_flask_detected(self):
        files = {"app.py": {"content_preview": "from flask import Flask\napp = Flask(__name__)"}}
        result = _detect_web_tech(files, [], "")
        assert "Flask" in result["frameworks"]

    def test_django_detected(self):
        files = {"settings.py": {"content_preview": "INSTALLED_APPS = ['django.contrib.auth']"}}
        result = _detect_web_tech(files, [], "")
        assert "Django" in result["frameworks"]

    def test_express_detected(self):
        files = {"server.js": {"content_preview": "const app = express(); app.get('/', handler);"}}
        result = _detect_web_tech(files, [], "")
        assert "Express.js" in result["frameworks"]

    def test_sqli_indicators(self):
        files = {"app.py": {"content_preview": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"}}
        result = _detect_web_tech(files, [], "")
        assert "sql_injection_possible" in result["vuln_indicators"]

    def test_xss_indicators(self):
        files = {"index.html": {"content_preview": "<script>document.write(innerHTML)</script>"}}
        result = _detect_web_tech(files, [], "")
        assert "xss_dom" in result["vuln_indicators"]

    def test_ssti_indicators(self):
        files = {"app.py": {"content_preview": "render_template_string(user_input)"}}
        result = _detect_web_tech(files, [], "")
        assert "ssti_possible" in result["vuln_indicators"]

    def test_command_injection_indicators(self):
        files = {"app.py": {"content_preview": "os.system(cmd)\nsubprocess.call(args)"}}
        result = _detect_web_tech(files, [], "")
        assert "command_injection" in result["vuln_indicators"]

    def test_endpoint_detection(self):
        files = {"app.py": {"content_preview": "@app.route('/login')\ndef login():\n    pass"}}
        result = _detect_web_tech(files, [], "")
        assert "/login" in result["endpoints"]

    def test_auth_mechanisms(self):
        files = {"app.py": {"content_preview": "jwt.decode(token)\nsession['user'] = name"}}
        result = _detect_web_tech(files, [], "")
        assert len(result["auth_mechanisms"]) > 0

    def test_description_analysis(self):
        result = _detect_web_tech({}, [], "A web application with login and search functionality")
        assert "auth_form" in result["input_points"]
        assert "search_field" in result["input_points"]

    def test_challenge_files_detection(self):
        challenge_files = {
            "app.py": {"path": "/tmp/app.py", "type": "text (.py)", "content_preview": ""},
            "templates/index.html": {"path": "/tmp/templates/index.html", "type": "text (.html)", "content_preview": ""},
        }
        result = _detect_web_tech(challenge_files, [], "")
        assert "python" in result["languages"]

    def test_php_detected(self):
        files = {"index.php": {"content_preview": "<?php echo $_POST['name']; ?>"}}
        result = _detect_web_tech(files, [], "")
        assert "php" in result["languages"]
        assert "PHP" in result["frameworks"]

    def test_server_tech_from_strings(self):
        strings = ["nginx/1.18.0", "Server: apache"]
        result = _detect_web_tech({}, strings, "")
        assert "nginx" in result["server_tech"]
        assert "apache" in result["server_tech"]

    def test_empty_inputs(self):
        result = _detect_web_tech({}, [], "")
        assert result["frameworks"] == []
        assert result["languages"] == []
        assert result["server_tech"] == []

    def test_deserialization_detected(self):
        files = {"app.py": {"content_preview": "data = pickle.loads(user_data)"}}
        result = _detect_web_tech(files, [], "")
        assert "deserialization" in result["vuln_indicators"]

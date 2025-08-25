#!/usr/bin/env python3
"""
Slack App for JIRA Card Creation
Provides OAuth authentication for JIRA and GitHub, with a web UI for easy card creation.
"""

import os
import json
import requests
import base64
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_from_directory
from slack_sdk import WebClient
from slack_sdk.oauth import AuthorizeUrlGenerator, RedirectUriPageRenderer
from slack_sdk.oauth.installation_store import FileInstallationStore
from slack_sdk.oauth.state_store import FileOAuthStateStore
from dotenv import load_dotenv
import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# Slack OAuth configuration
SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

# OAuth stores
installation_store = FileInstallationStore(base_dir="./data")
state_store = FileOAuthStateStore(expiration_seconds=600, base_dir="./data")

class JiraOAuth:
    """Handle JIRA OAuth authentication"""
    
    def __init__(self):
        self.client_id = os.getenv('JIRA_CLIENT_ID')
        self.client_secret = os.getenv('JIRA_CLIENT_SECRET')
        self.redirect_uri = os.getenv('JIRA_REDIRECT_URI', 'http://localhost:3000/auth/jira/callback')
    
    def get_auth_url(self, state):
        """Generate JIRA OAuth authorization URL"""
        base_url = "https://auth.atlassian.com/authorize"
        params = {
            'audience': 'api.atlassian.com',
            'client_id': self.client_id,
            'scope': 'read:jira-work write:jira-work offline_access',
            'redirect_uri': self.redirect_uri,
            'state': state,
            'response_type': 'code',
            'prompt': 'consent'
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{query_string}"
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        token_url = "https://auth.atlassian.com/oauth/token"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_accessible_resources(self, access_token):
        """Get JIRA instances accessible to the user"""
        url = "https://api.atlassian.com/oauth/token/accessible-resources"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return []

class GitHubOAuth:
    """Handle GitHub OAuth authentication"""
    
    def __init__(self):
        self.client_id = os.getenv('GITHUB_CLIENT_ID')
        self.client_secret = os.getenv('GITHUB_CLIENT_SECRET')
        self.redirect_uri = os.getenv('GITHUB_REDIRECT_URI', 'http://localhost:3000/auth/github/callback')
    
    def get_auth_url(self, state):
        """Generate GitHub OAuth authorization URL"""
        base_url = "https://github.com/login/oauth/authorize"
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'user:email',
            'state': state
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{query_string}"
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        token_url = "https://github.com/login/oauth/access_token"
        
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        
        headers = {'Accept': 'application/json'}
        response = requests.post(token_url, data=data, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_user_info(self, access_token):
        """Get GitHub user information"""
        url = "https://api.github.com/user"
        headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None

class JiraClient:
    """JIRA API client with OAuth support"""
    
    def __init__(self, access_token, cloud_id, base_url):
        self.access_token = access_token
        self.cloud_id = cloud_id
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def get_projects(self):
        """Get all projects"""
        url = f"{self.base_url}/rest/api/3/project"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        return []
    
    def get_issue_types(self, project_key):
        """Get issue types for a project"""
        url = f"{self.base_url}/rest/api/3/issue/createmeta"
        params = {
            'projectKeys': project_key,
            'expand': 'projects.issuetypes'
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        if response.status_code == 200:
            data = response.json()
            issue_types = {}
            
            for project in data.get('projects', []):
                if project.get('key') == project_key:
                    for issue_type in project.get('issuetypes', []):
                        issue_types[issue_type['name']] = issue_type['id']
                    break
            
            return issue_types
        return {}
    
    def create_issue(self, project_key, title, description, issue_type="Production Change", priority="Medium", due_date=None):
        """Create a JIRA issue"""
        issue_types = self.get_issue_types(project_key)
        
        if issue_type not in issue_types:
            return {'error': f"Issue type '{issue_type}' not found"}
        
        issue_data = {
            "fields": {
                "project": {"key": project_key},
                "summary": title,
                "issuetype": {"id": issue_types[issue_type]}
            }
        }
        
        # Add description for non-Production Change types
        if issue_type != "Production Change":
            issue_data["fields"]["description"] = {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": description}]
                }]
            }
        
        # Add due date if provided
        if due_date:
            issue_data["fields"]["duedate"] = due_date
        
        url = f"{self.base_url}/rest/api/3/issue"
        response = requests.post(url, headers=self.headers, json=issue_data)
        
        if response.status_code == 201:
            result = response.json()
            return {
                'key': result.get('key'),
                'url': f"{self.base_url}/browse/{result.get('key')}",
                'id': result.get('id')
            }
        else:
            return {'error': f"Failed to create issue: {response.text}"}

# Initialize OAuth handlers
jira_oauth = JiraOAuth()
github_oauth = GitHubOAuth()

@app.route('/')
def home():
    """Home page with authentication status"""
    return render_template('index.html', 
                         jira_authenticated='jira_token' in session,
                         github_authenticated='github_token' in session)

@app.route('/auth/jira')
def auth_jira():
    """Initiate JIRA OAuth flow"""
    state = secrets.token_urlsafe(32)
    session['jira_oauth_state'] = state
    auth_url = jira_oauth.get_auth_url(state)
    return redirect(auth_url)

@app.route('/auth/jira/callback')
def auth_jira_callback():
    """Handle JIRA OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or state != session.get('jira_oauth_state'):
        return jsonify({'error': 'Invalid OAuth callback'}), 400
    
    # Exchange code for token
    token_data = jira_oauth.exchange_code_for_token(code)
    if not token_data:
        return jsonify({'error': 'Failed to get access token'}), 400
    
    # Get accessible resources
    resources = jira_oauth.get_accessible_resources(token_data['access_token'])
    
    # Store authentication data
    session['jira_token'] = token_data['access_token']
    session['jira_resources'] = resources
    
    return redirect(url_for('home'))

@app.route('/auth/github')
def auth_github():
    """Initiate GitHub OAuth flow"""
    state = secrets.token_urlsafe(32)
    session['github_oauth_state'] = state
    auth_url = github_oauth.get_auth_url(state)
    return redirect(auth_url)

@app.route('/auth/github/callback')
def auth_github_callback():
    """Handle GitHub OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or state != session.get('github_oauth_state'):
        return jsonify({'error': 'Invalid OAuth callback'}), 400
    
    # Exchange code for token
    token_data = github_oauth.exchange_code_for_token(code)
    if not token_data:
        return jsonify({'error': 'Failed to get access token'}), 400
    
    # Get user info
    user_info = github_oauth.get_user_info(token_data['access_token'])
    
    # Store authentication data
    session['github_token'] = token_data['access_token']
    session['github_user'] = user_info
    
    return redirect(url_for('home'))

@app.route('/create-card')
def create_card_form():
    """Show card creation form"""
    if 'jira_token' not in session:
        return redirect(url_for('auth_jira'))
    
    # Get JIRA projects
    jira_resource = session['jira_resources'][0] if session['jira_resources'] else None
    if not jira_resource:
        return jsonify({'error': 'No JIRA resources available'}), 400
    
    jira_client = JiraClient(
        session['jira_token'],
        jira_resource['id'],
        jira_resource['url']
    )
    
    projects = jira_client.get_projects()
    
    return render_template('create_card.html', 
                         projects=projects,
                         github_authenticated='github_token' in session)

@app.route('/api/projects/<project_key>/issue-types')
def get_issue_types(project_key):
    """Get issue types for a project"""
    if 'jira_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    jira_resource = session['jira_resources'][0]
    jira_client = JiraClient(
        session['jira_token'],
        jira_resource['id'],
        jira_resource['url']
    )
    
    issue_types = jira_client.get_issue_types(project_key)
    return jsonify(issue_types)

@app.route('/api/create-issue', methods=['POST'])
def create_issue():
    """Create JIRA issue via API"""
    if 'jira_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    jira_resource = session['jira_resources'][0]
    jira_client = JiraClient(
        session['jira_token'],
        jira_resource['id'],
        jira_resource['url']
    )
    
    result = jira_client.create_issue(
        project_key=data['project'],
        title=data['title'],
        description=data['description'],
        issue_type=data.get('issue_type', 'Production Change'),
        priority=data.get('priority', 'Medium'),
        due_date=data.get('due_date')
    )
    
    return jsonify(result)

@app.route('/api/jira/test', methods=['POST'])
def test_jira_connection():
    """Test JIRA connection with provided credentials"""
    data = request.json
    domain = data.get('domain')
    email = data.get('email')
    token = data.get('token')
    
    if not all([domain, email, token]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Test connection by getting user info
    auth_string = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_string}',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(f'https://{domain}/rest/api/3/myself', headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            return jsonify({
                'success': True,
                'user': {
                    'displayName': user_info.get('displayName'),
                    'emailAddress': user_info.get('emailAddress')
                }
            })
        else:
            return jsonify({'error': 'Authentication failed'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jira/create-issue', methods=['POST'])
def create_jira_issue():
    """Create a JIRA issue via server-side proxy"""
    data = request.json
    
    # Extract credentials and issue data
    domain = data.get('domain')
    email = data.get('email')
    token = data.get('token')
    issue_data = data.get('issue_data')
    
    if not all([domain, email, token, issue_data]):
        return jsonify({'error': 'Missing required data'}), 400
    
    # Create JIRA issue
    auth_string = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_string}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f'https://{domain}/rest/api/3/issue',
            headers=headers,
            json=issue_data
        )
        
        if response.status_code == 201:
            result = response.json()
            return jsonify({
                'success': True,
                'key': result.get('key'),
                'id': result.get('id'),
                'url': f'https://{domain}/browse/{result.get("key")}'
            })
        else:
            error_data = response.json() if response.content else {'message': 'Unknown error'}
            return jsonify({'error': error_data}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/github/test', methods=['POST'])
def test_github_connection():
    """Test GitHub connection with provided token"""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Missing token'}), 400
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        response = requests.get('https://api.github.com/user', headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            return jsonify({
                'success': True,
                'user': {
                    'login': user_info.get('login'),
                    'name': user_info.get('name')
                }
            })
        else:
            return jsonify({'error': 'Authentication failed'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/github/version', methods=['POST'])
def get_github_version():
    """Get latest version/tag from GitHub repository"""
    data = request.json
    token = data.get('token')
    repo = data.get('repo')  # format: owner/repository
    
    if not token or not repo:
        return jsonify({'error': 'Missing token or repository'}), 400
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        # Get latest release
        response = requests.get(f'https://api.github.com/repos/{repo}/releases/latest', headers=headers)
        
        if response.status_code == 200:
            release_info = response.json()
            tag_name = release_info.get('tag_name', '')
            # Remove 'v' prefix if present
            version = tag_name.lstrip('v')
            return jsonify({
                'success': True,
                'version': version,
                'tag_name': tag_name
            })
        elif response.status_code == 404:
            # No releases found, try to get tags
            response = requests.get(f'https://api.github.com/repos/{repo}/tags', headers=headers)
            if response.status_code == 200:
                tags = response.json()
                if tags:
                    latest_tag = tags[0]['name']
                    version = latest_tag.lstrip('v')
                    return jsonify({
                        'success': True,
                        'version': version,
                        'tag_name': latest_tag
                    })
                else:
                    return jsonify({
                        'success': True,
                        'version': '0.0.0',
                        'tag_name': 'v0.0.0'
                    })
            else:
                return jsonify({'error': 'Could not fetch repository information'}), 404
        else:
            return jsonify({'error': 'Repository not found or access denied'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/jira/update-custom-fields', methods=['POST'])
def update_jira_custom_fields():
    """Update custom fields for Production Change Details and Rollback Script"""
    data = request.json
    
    # Extract credentials and field data
    domain = data.get('domain')
    email = data.get('email')
    token = data.get('token')
    issue_key = data.get('issue_key')
    production_details = data.get('production_details')
    rollback_script = data.get('rollback_script')
    
    if not all([domain, email, token, issue_key]):
        print(f"Missing required data: domain={domain}, email={email}, token={'***' if token else None}, issue_key={issue_key}")
        return jsonify({'error': 'Missing required data'}), 400
    
    print(f"Updating custom fields for issue: {issue_key}")
    print(f"Production details length: {len(production_details) if production_details else 0}")
    print(f"Rollback script length: {len(rollback_script) if rollback_script else 0}")
    
    # Update JIRA issue custom fields
    auth_string = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_string}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Get the issue to find custom field IDs
    try:
        get_response = requests.get(
            f'https://{domain}/rest/api/3/issue/{issue_key}',
            headers=headers
        )
        print(f"Get issue response: {get_response.status_code}")
        if get_response.ok:
            issue_data = get_response.json()
            fields = issue_data.get('fields', {})
            print(f"Available fields: {list(fields.keys())}")
            
            # Look for custom fields that might be Production Change Details and Rollback Script
            custom_fields = {}
            for field_id, field_value in fields.items():
                if field_id.startswith('customfield_'):
                    custom_fields[field_id] = field_value
            
            print(f"Custom fields found: {list(custom_fields.keys())}")
            
            # Try to find fields by looking at field metadata
            meta_response = requests.get(
                f'https://{domain}/rest/api/3/issue/{issue_key}/editmeta',
                headers=headers
            )
            if meta_response.ok:
                meta_data = meta_response.json()
                print(f"Edit metadata: {meta_data}")
                
                # Look for fields with names containing "Production Change" or "Rollback"
                update_fields = {}
                for field_id, field_info in meta_data.get('fields', {}).items():
                    field_name = field_info.get('name', '').lower()
                    if 'production change detail' in field_name and production_details:
                        # Process markdown content for custom fields - create single code block
                        content = []
                        lines = production_details.split('\n')
                        current_paragraph = []
                        all_code_lines = []
                        in_code_block = False
                        
                        for line in lines:
                            original_line = line
                            line_stripped = line.strip()
                            
                            if line_stripped.startswith('```'):
                                if in_code_block:
                                    # End code block
                                    in_code_block = False
                                else:
                                    # Start code block - end current paragraph first
                                    if current_paragraph:
                                        content.append({
                                            "type": "paragraph",
                                            "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                        })
                                        current_paragraph = []
                                    in_code_block = True
                            elif in_code_block:
                                # Inside code block - collect all lines
                                all_code_lines.append(original_line)
                            elif not line_stripped:
                                # Empty line outside code block
                                if current_paragraph:
                                    content.append({
                                        "type": "paragraph",
                                        "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                    })
                                    current_paragraph = []
                            elif line_stripped.startswith('### '):
                                # Heading
                                if current_paragraph:
                                    content.append({
                                        "type": "paragraph", 
                                        "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                    })
                                    current_paragraph = []
                                content.append({
                                    "type": "heading",
                                    "attrs": {"level": 3},
                                    "content": [{"type": "text", "text": line_stripped[4:]}]
                                })
                            else:
                                # Regular text
                                current_paragraph.append(line_stripped)
                        
                        # Add remaining paragraph
                        if current_paragraph:
                            content.append({
                                "type": "paragraph",
                                "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                            })
                        
                        # Add single unified code block at the end if we have code lines
                        if all_code_lines:
                            content.append({
                                "type": "codeBlock",
                                "attrs": {},
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "\n".join(all_code_lines)
                                    }
                                ]
                            })
                        
                        update_fields[field_id] = {
                            "type": "doc",
                            "version": 1,
                            "content": content
                        }
                        print(f"Found Production Change Details field: {field_id}")
                    elif 'rollback' in field_name and rollback_script:
                        # Process markdown content for rollback script custom field - create single code block
                        content = []
                        lines = rollback_script.split('\n')
                        current_paragraph = []
                        all_code_lines = []
                        in_code_block = False
                        
                        for line in lines:
                            original_line = line
                            line_stripped = line.strip()
                            
                            if line_stripped.startswith('```'):
                                if in_code_block:
                                    # End code block
                                    in_code_block = False
                                else:
                                    # Start code block - end current paragraph first
                                    if current_paragraph:
                                        content.append({
                                            "type": "paragraph",
                                            "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                        })
                                        current_paragraph = []
                                    in_code_block = True
                            elif in_code_block:
                                # Inside code block - collect all lines
                                all_code_lines.append(original_line)
                            elif not line_stripped:
                                # Empty line outside code block
                                if current_paragraph:
                                    content.append({
                                        "type": "paragraph",
                                        "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                    })
                                    current_paragraph = []
                            else:
                                # Regular text
                                current_paragraph.append(line_stripped)
                        
                        # Add remaining paragraph
                        if current_paragraph:
                            content.append({
                                "type": "paragraph",
                                "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                            })
                        
                        # Add single unified code block at the end if we have code lines
                        if all_code_lines:
                            content.append({
                                "type": "codeBlock",
                                "attrs": {},
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "\n".join(all_code_lines)
                                    }
                                ]
                            })
                        
                        update_fields[field_id] = {
                            "type": "doc",
                            "version": 1,
                            "content": content
                        }
                        print(f"Found Rollback Script field: {field_id}")
                
                if update_fields:
                    update_data = {"fields": update_fields}
                    
                    response = requests.put(
                        f'https://{domain}/rest/api/3/issue/{issue_key}',
                        headers=headers,
                        json=update_data
                    )
                    
                    print(f"Custom field update response: {response.status_code}")
                    if response.content:
                        print(f"Custom field update response: {response.text}")
                    
                    if response.status_code == 204:
                        return jsonify({
                            'success': True,
                            'message': 'Custom fields updated successfully',
                            'updated_fields': list(update_fields.keys())
                        })
                    else:
                        error_data = response.json() if response.content else {'message': 'Unknown error'}
                        return jsonify({'error': error_data}), response.status_code
                else:
                    print("No matching custom fields found, trying to update description instead")
                    # Fallback: Update the description field with the production details
                    if production_details:
                        description_content = {
                            "type": "doc",
                            "version": 1,
                            "content": [
                                {
                                    "type": "heading",
                                    "attrs": {"level": 3},
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "Production Change Details"
                                        }
                                    ]
                                }
                            ]
                        }
                        
                        # Process production change details lines - create single code block
                        lines = production_details.split('\n')
                        current_paragraph = []
                        all_code_lines = []
                        in_code_block = False
                        
                        for line in lines:
                            original_line = line
                            line_stripped = line.strip()
                            
                            if line_stripped.startswith('```'):
                                if in_code_block:
                                    # End code block
                                    in_code_block = False
                                else:
                                    # Start code block - end current paragraph first
                                    if current_paragraph:
                                        description_content["content"].append({
                                            "type": "paragraph",
                                            "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                        })
                                        current_paragraph = []
                                    in_code_block = True
                            elif in_code_block:
                                # Inside code block - collect all lines
                                all_code_lines.append(original_line)
                            elif not line_stripped:
                                if current_paragraph:
                                    description_content["content"].append({
                                        "type": "paragraph",
                                        "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                    })
                                    current_paragraph = []
                            elif line_stripped.startswith('### '):
                                # Heading
                                if current_paragraph:
                                    description_content["content"].append({
                                        "type": "paragraph", 
                                        "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                                    })
                                    current_paragraph = []
                                description_content["content"].append({
                                    "type": "heading",
                                    "attrs": {"level": 3},
                                    "content": [{"type": "text", "text": line_stripped[4:]}]
                                })
                            else:
                                # Regular text
                                current_paragraph.append(line_stripped)
                        
                        if current_paragraph:
                            description_content["content"].append({
                                "type": "paragraph",
                                "content": [{"type": "text", "text": " ".join(current_paragraph)}]
                            })
                        
                        # Add single unified code block at the end if we have code lines
                        if all_code_lines:
                            description_content["content"].append({
                                "type": "codeBlock",
                                "attrs": {},
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "\n".join(all_code_lines)
                                    }
                                ]
                            })
                        
                        # Add rollback script if available
                        if rollback_script:
                            description_content["content"].append({
                                "type": "heading",
                                "attrs": {"level": 3},
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "Production Change Rollback Script"
                                    }
                                ]
                            })
                            
                            # Process rollback script lines - create single code block
                            rollback_lines = rollback_script.split('\n')
                            rollback_paragraph = []
                            rollback_all_code_lines = []
                            rollback_in_code_block = False
                            
                            for line in rollback_lines:
                                original_line = line
                                line_stripped = line.strip()
                                
                                if line_stripped.startswith('```'):
                                    if rollback_in_code_block:
                                        # End code block
                                        rollback_in_code_block = False
                                    else:
                                        # Start code block - end current paragraph first
                                        if rollback_paragraph:
                                            description_content["content"].append({
                                                "type": "paragraph",
                                                "content": [{"type": "text", "text": " ".join(rollback_paragraph)}]
                                            })
                                            rollback_paragraph = []
                                        rollback_in_code_block = True
                                elif rollback_in_code_block:
                                    # Inside code block - collect all lines
                                    rollback_all_code_lines.append(original_line)
                                elif not line_stripped:
                                    if rollback_paragraph:
                                        description_content["content"].append({
                                            "type": "paragraph",
                                            "content": [{"type": "text", "text": " ".join(rollback_paragraph)}]
                                        })
                                        rollback_paragraph = []
                                else:
                                    rollback_paragraph.append(line_stripped)
                            
                            if rollback_paragraph:
                                description_content["content"].append({
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": " ".join(rollback_paragraph)}]
                                })
                            
                            # Add single unified code block at the end if we have code lines
                            if rollback_all_code_lines:
                                description_content["content"].append({
                                    "type": "codeBlock",
                                    "attrs": {},
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "\n".join(rollback_all_code_lines)
                                        }
                                    ]
                                })
                        
                        update_data = {
                            "fields": {
                                "description": description_content
                            }
                        }
                        
                        response = requests.put(
                            f'https://{domain}/rest/api/3/issue/{issue_key}',
                            headers=headers,
                            json=update_data
                        )
                        
                        print(f"Description update response: {response.status_code}")
                        if response.content:
                            print(f"Description update response: {response.text}")
                        
                        if response.status_code == 204:
                            return jsonify({
                                'success': True,
                                'message': 'Description updated with production details',
                                'fallback': True
                            })
                        else:
                            error_data = response.json() if response.content else {'message': 'Unknown error'}
                            return jsonify({'error': error_data}), response.status_code
                    else:
                        return jsonify({'error': 'No matching custom fields found and no production details to add'}), 404
            else:
                return jsonify({'error': 'Could not get field metadata'}), 400
        else:
            return jsonify({'error': 'Could not get issue data'}), 400
    except Exception as e:
        print(f"Exception updating custom fields: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/jira/add-comment', methods=['POST'])
def add_jira_comment():
    """Add a comment to a JIRA issue"""
    data = request.json
    
    # Extract credentials and comment data
    domain = data.get('domain')
    email = data.get('email')
    token = data.get('token')
    issue_key = data.get('issue_key')
    comment_body = data.get('comment_body')
    
    if not all([domain, email, token, issue_key, comment_body]):
        return jsonify({'error': 'Missing required data'}), 400
    
    # Add comment to JIRA issue
    auth_string = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_string}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    comment_data = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": comment_body
                        }
                    ]
                }
            ]
        }
    }
    
    try:
        response = requests.post(
            f'https://{domain}/rest/api/3/issue/{issue_key}/comment',
            headers=headers,
            json=comment_data
        )
        
        if response.status_code == 201:
            result = response.json()
            return jsonify({
                'success': True,
                'comment_id': result.get('id')
            })
        else:
            error_data = response.json() if response.content else {'message': 'Unknown error'}
            return jsonify({'error': error_data}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/github/create-branch', methods=['POST'])
def create_github_branch():
    """Create a new branch in a GitHub repository"""
    data = request.json
    
    token = data.get('token')
    repo = data.get('repo')  # format: owner/repository
    branch_name = data.get('branch_name')
    base_branch = data.get('base_branch', 'main')
    
    if not all([token, repo, branch_name]):
        return jsonify({'error': 'Missing required data'}), 400
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        # Get the SHA of the base branch
        response = requests.get(f'https://api.github.com/repos/{repo}/git/ref/heads/{base_branch}', headers=headers)
        
        if response.status_code != 200:
            return jsonify({'error': f'Could not find base branch {base_branch}'}), 404
        
        base_sha = response.json()['object']['sha']
        
        # Create the new branch
        branch_data = {
            'ref': f'refs/heads/{branch_name}',
            'sha': base_sha
        }
        
        response = requests.post(f'https://api.github.com/repos/{repo}/git/refs', headers=headers, json=branch_data)
        
        if response.status_code == 201:
            return jsonify({
                'success': True,
                'branch_name': branch_name,
                'url': f'https://github.com/{repo}/tree/{branch_name}'
            })
        else:
            error_data = response.json() if response.content else {'message': 'Unknown error'}
            return jsonify({'error': error_data}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/change_templates/<filename>')
def serve_template(filename):
    """Serve template files from change_templates directory"""
    return send_from_directory('change_templates', filename)

@app.route('/api/test')
def test_api():
    return jsonify({'status': 'success', 'message': 'API is working correctly'})

@app.route('/api/jira/delete-issue', methods=['DELETE'])
def delete_jira_issue():
    try:
        data = request.json
        domain = data.get('domain')
        email = data.get('email')
        token = data.get('token')
        issue_key = data.get('issueKey')
        
        if not all([domain, email, token, issue_key]):
            return jsonify({'error': 'Missing required data'}), 400
        
        # Create basic auth header
        auth_string = f"{email}:{token}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            'Authorization': f'Basic {auth_b64}',
            'Content-Type': 'application/json'
        }
        
        # Delete JIRA issue
        url = f"https://{domain}/rest/api/3/issue/{issue_key}"
        response = requests.delete(url, headers=headers)
        
        print(f"JIRA delete response: {response.status_code}")
        
        if response.status_code == 204:
            return jsonify({'success': True, 'message': f'Issue {issue_key} deleted successfully'})
        else:
            error_data = response.text
            try:
                error_data = response.json()
            except:
                pass
            print(f"JIRA delete error: {error_data}")
            return jsonify({'success': False, 'error': error_data}), response.status_code
            
    except Exception as e:
        print(f"Delete JIRA issue error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/github/delete-branches', methods=['DELETE'])
def delete_github_branches():
    try:
        data = request.json
        token = data.get('token')
        version = data.get('version')
        deployment_type = data.get('deploymentType')
        
        if not all([token, version, deployment_type]):
            return jsonify({'error': 'Missing required data'}), 400
        
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        deleted_branches = []
        errors = []
        
        # Determine which repositories to delete branches from
        repos_to_process = []
        if deployment_type in ['web-only', 'web-api']:
            repos_to_process.append('leap-web')
        if deployment_type in ['api-only', 'web-api', 'public-api']:
            repos_to_process.append('leap-api')
        
        for repo in repos_to_process:
            branch_name = f"release/{version}"
            
            # Delete branch
            delete_url = f"https://api.github.com/repos/leap-labs/{repo}/git/refs/heads/release/{version}"
            delete_response = requests.delete(delete_url, headers=headers)
            
            print(f"GitHub delete branch response for {repo}: {delete_response.status_code}")
            
            if delete_response.status_code == 204:
                deleted_branches.append(f"{repo}:{branch_name}")
            elif delete_response.status_code == 422:
                # Branch doesn't exist - not an error
                print(f"Branch {branch_name} doesn't exist in {repo}")
            else:
                error_msg = f"Failed to delete {branch_name} from {repo}"
                try:
                    error_data = delete_response.json()
                    error_msg += f": {error_data.get('message', 'Unknown error')}"
                except:
                    pass
                errors.append(error_msg)
        
        if errors:
            return jsonify({
                'success': False, 
                'error': '; '.join(errors),
                'deleted_branches': deleted_branches
            }), 400
        else:
            return jsonify({
                'success': True, 
                'message': 'Branches deleted successfully',
                'deleted_branches': deleted_branches
            })
            
    except Exception as e:
        print(f"Delete GitHub branches error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logout')
def logout():
    """Clear all authentication data"""
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Create data directory for OAuth stores
    os.makedirs('./data', exist_ok=True)
    os.makedirs('./templates', exist_ok=True)
    
    app.run(host='0.0.0.0', port=5000, debug=True)

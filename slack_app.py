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
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
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

@app.route('/logout')
def logout():
    """Clear all authentication data"""
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Create data directory for OAuth stores
    os.makedirs('./data', exist_ok=True)
    os.makedirs('./templates', exist_ok=True)
    
    app.run(host='0.0.0.0', port=3000, debug=True)

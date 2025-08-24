#!/usr/bin/env python3
"""
JIRA CLI Application
Creates JIRA cards with title and description via command line interface.
"""

import os
import sys
import json
import requests
import click
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

class JiraClient:
    def __init__(self):
        self.token = os.getenv('JIRA_TOKEN')
        self.base_url = os.getenv('JIRA_BASE_URL')
        self.email = os.getenv('JIRA_EMAIL')
        self.board_url = os.getenv('JIRA_BOARD')
        
        if not all([self.token, self.base_url, self.email]):
            click.echo("Error: Missing required environment variables. Check your .env file.", err=True)
            sys.exit(1)
        
        # Extract project key from board URL
        self.project_key = self._extract_project_key()
        
        self.headers = {
            'Authorization': f'Basic {self._get_auth_string()}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def _get_auth_string(self):
        """Create base64 encoded auth string for JIRA API"""
        import base64
        auth_str = f"{self.email}:{self.token}"
        return base64.b64encode(auth_str.encode()).decode()
    
    def _extract_project_key(self):
        """Extract project key from board URL"""
        if self.board_url:
            # Extract project key from URL like: https://leap.atlassian.net/jira/software/c/projects/DEVOPS/boards/115
            parts = self.board_url.split('/')
            try:
                project_index = parts.index('projects') + 1
                return parts[project_index]
            except (ValueError, IndexError):
                pass
        
        # Default fallback - you may need to adjust this
        return "DEVOPS"
    
    def get_project_info(self):
        """Get project information to validate connection"""
        url = f"{self.base_url}/rest/api/3/project/{self.project_key}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            click.echo(f"Error connecting to JIRA: {e}", err=True)
            return None
    
    def get_issue_types(self):
        """Get available issue types for the project"""
        # Try the createmeta endpoint first (more reliable)
        url = f"{self.base_url}/rest/api/3/issue/createmeta"
        params = {
            'projectKeys': self.project_key,
            'expand': 'projects.issuetypes'
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            issue_types = {}
            projects = data.get('projects', [])
            
            for project in projects:
                if project.get('key') == self.project_key:
                    for issue_type in project.get('issuetypes', []):
                        issue_types[issue_type['name']] = issue_type['id']
                    break
            
            # Fallback: if no issue types found, try alternative endpoint
            if not issue_types:
                fallback_url = f"{self.base_url}/rest/api/3/project/{self.project_key}"
                fallback_response = requests.get(fallback_url, headers=self.headers)
                fallback_response.raise_for_status()
                project_data = fallback_response.json()
                
                for issue_type in project_data.get('issueTypes', []):
                    issue_types[issue_type['name']] = issue_type['id']
            
            return issue_types
            
        except requests.exceptions.RequestException as e:
            click.echo(f"Error fetching issue types: {e}", err=True)
            # Return default issue types as fallback
            return {
                'Task': '10001',
                'Story': '10002', 
                'Bug': '10003',
                'Epic': '10000'
            }
    
    def create_issue(self, title, description, issue_type="Task", priority="Medium"):
        """Create a JIRA issue"""
        # Get issue types to find the correct ID
        issue_types = self.get_issue_types()
        
        if issue_type not in issue_types:
            available_types = list(issue_types.keys())
            click.echo(f"Error: Issue type '{issue_type}' not found. Available types: {available_types}", err=True)
            return None
        
        # Priority mapping
        priority_map = {
            "Highest": "1",
            "High": "2", 
            "Medium": "3",
            "Low": "4",
            "Lowest": "5"
        }
        
        priority_id = priority_map.get(priority, "3")  # Default to Medium
        
        issue_data = {
            "fields": {
                "project": {
                    "key": self.project_key
                },
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "id": issue_types[issue_type]
                },
                "priority": {
                    "id": priority_id
                }
            }
        }
        
        url = f"{self.base_url}/rest/api/3/issue"
        
        try:
            response = requests.post(url, headers=self.headers, json=issue_data)
            response.raise_for_status()
            
            result = response.json()
            issue_key = result.get('key')
            issue_url = f"{self.base_url}/browse/{issue_key}"
            
            return {
                'key': issue_key,
                'url': issue_url,
                'id': result.get('id')
            }
            
        except requests.exceptions.RequestException as e:
            click.echo(f"Error creating JIRA issue: {e}", err=True)
            if hasattr(e.response, 'text'):
                click.echo(f"Response: {e.response.text}", err=True)
            return None


@click.group()
def cli():
    """JIRA CLI - Create and manage JIRA cards from command line"""
    pass


@cli.command()
@click.option('--title', '-t', required=True, help='Title/Summary of the JIRA card')
@click.option('--description', '-d', required=True, help='Description of the JIRA card')
@click.option('--type', '-T', default='Task', help='Issue type (default: Task)')
@click.option('--priority', '-p', default='Medium', 
              type=click.Choice(['Highest', 'High', 'Medium', 'Low', 'Lowest']),
              help='Priority level (default: Medium)')
@click.option('--dry-run', is_flag=True, help='Show what would be created without actually creating it')
def create(title, description, type, priority, dry_run):
    """Create a new JIRA card"""
    
    if dry_run:
        click.echo("DRY RUN - Would create JIRA card with:")
        click.echo(f"  Title: {title}")
        click.echo(f"  Description: {description}")
        click.echo(f"  Type: {type}")
        click.echo(f"  Priority: {priority}")
        return
    
    jira = JiraClient()
    
    # Validate connection
    project_info = jira.get_project_info()
    if not project_info:
        sys.exit(1)
    
    click.echo(f"Creating JIRA card in project: {project_info.get('name', jira.project_key)}")
    
    # Create the issue
    result = jira.create_issue(title, description, type, priority)
    
    if result:
        click.echo(f"✅ Successfully created JIRA card!")
        click.echo(f"   Key: {result['key']}")
        click.echo(f"   URL: {result['url']}")
    else:
        click.echo("❌ Failed to create JIRA card")
        sys.exit(1)


@cli.command()
def info():
    """Show JIRA connection information"""
    jira = JiraClient()
    
    click.echo("JIRA Configuration:")
    click.echo(f"  Base URL: {jira.base_url}")
    click.echo(f"  Email: {jira.email}")
    click.echo(f"  Project Key: {jira.project_key}")
    
    # Test connection
    project_info = jira.get_project_info()
    if project_info:
        click.echo(f"  Project Name: {project_info.get('name')}")
        click.echo("  ✅ Connection successful")
        
        # Show available issue types
        issue_types = jira.get_issue_types()
        if issue_types:
            click.echo(f"  Available Issue Types: {', '.join(issue_types.keys())}")
    else:
        click.echo("  ❌ Connection failed")


if __name__ == '__main__':
    cli()

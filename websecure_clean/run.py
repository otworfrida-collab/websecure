"""
WebSecure - Application Entry Point
Run locally:  python run.py
Production:   gunicorn run:app
"""

import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'development') == 'development'
    print("""
╔══════════════════════════════════════════════╗
║         WebSecure — Starting Up              ║
╠══════════════════════════════════════════════╣
║  Dashboard: http://127.0.0.1:5000/dashboard  ║
║  Register:  http://127.0.0.1:5000/register   ║
╚══════════════════════════════════════════════╝
    """)
    app.run(debug=debug, host='0.0.0.0', port=port)

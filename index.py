# Vercel serverless entry point
from app import app

# Vercel expects a handler function
def handler(request):
    return app(request.environ, lambda status, headers: app.wsgi_app.start_response(status, headers))

import json
import jwt
from datetime import datetime, timedelta
from functools import wraps
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.conf import settings
from .models import Post, Comment

# Helper to parse JSON
def parse_body(request):
    try:
        return json.loads(request.body)
    except:
        return {}

# JWT utilities
def generate_jwt(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token

def decode_jwt(token):
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# Decorator
def jwt_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header required'}, status=401)
        token = auth_header.split(' ')[1]
        payload = decode_jwt(token)
        if not payload:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)
        request.user_jwt = payload
        return view_func(request, *args, **kwargs)
    return wrapper

@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=400)
    data = parse_body(request)
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return JsonResponse({'error': 'All fields required'}, status=400)
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username taken'}, status=400)
    User.objects.create_user(username=username, email=email, password=password)
    return JsonResponse({'message': 'User registered'})

@csrf_exempt
def user_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=400)
    
    data = parse_body(request)
    username = data.get('username')
    password = data.get('password')

    user = authenticate(username=username, password=password)
    if user:
        token = generate_jwt(user)
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return JsonResponse({'token': token}, status=200)
    else:
        return JsonResponse({'error': 'Invalid credentials'}, status=400)

@csrf_exempt
@jwt_required
def create_post(request):
    data = parse_body(request)
    title = data.get('title')
    content = data.get('content')
    if not title or not content:
        return JsonResponse({'error': 'Title and content required'}, status=400)
    try:
        user = User.objects.get(id=request.user_jwt['user_id'])
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    post = Post.objects.create(author=user, title=title, content=content)
    return JsonResponse({'message': 'Post created', 'post_id': post.id})

def list_posts(request):
    posts = Post.objects.all().order_by('-created_at')
    data = []
    for post in posts:
        data.append({
            'id': post.id,
            'title': post.title,
            'author': post.author.username,
            'content': post.content,
            'created_at': post.created_at
        })
    return JsonResponse({'posts': data})

def post_detail(request, id):
    try:
        post = Post.objects.get(id=id)
    except Post.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)
    comments = post.comments.all().order_by('-created_at')
    comment_list = [{
        'id': c.id,
        'user': c.user.username,
        'text': c.text,
        'created_at': c.created_at
    } for c in comments]
    return JsonResponse({
        'id': post.id,
        'title': post.title,
        'author': post.author.username,
        'content': post.content,
        'created_at': post.created_at,
        'comments': comment_list
    })

@csrf_exempt
@jwt_required
def add_comment(request, id):
    data = parse_body(request)
    text = data.get('text')
    if not text:
        return JsonResponse({'error': 'Text required'}, status=400)
    try:
        post = Post.objects.get(id=id)
    except Post.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)
    try:
        user = User.objects.get(id=request.user_jwt['user_id'])
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    Comment.objects.create(post=post, user=user, text=text)
    return JsonResponse({'message': 'Comment added'})

from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import re
from src.models import db, User

auth_bp = Blueprint('auth', __name__)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
    
    if not re.search(r'[A-Za-z]', password):
        return False, "كلمة المرور يجب أن تحتوي على أحرف"
    
    if not re.search(r'[0-9]', password):
        return False, "كلمة المرور يجب أن تحتوي على أرقام"
    
    return True, "كلمة المرور صالحة"

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'لم يتم إرسال بيانات'
            }), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirmPassword', '')
        
        # Validation
        if not username:
            return jsonify({
                'success': False,
                'message': 'اسم المستخدم مطلوب'
            }), 400
        
        if len(username) < 3:
            return jsonify({
                'success': False,
                'message': 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل'
            }), 400
        
        if not email:
            return jsonify({
                'success': False,
                'message': 'البريد الإلكتروني مطلوب'
            }), 400
        
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'صيغة البريد الإلكتروني غير صحيحة'
            }), 400
        
        if not password:
            return jsonify({
                'success': False,
                'message': 'كلمة المرور مطلوبة'
            }), 400
        
        if password != confirm_password:
            return jsonify({
                'success': False,
                'message': 'كلمتا المرور غير متطابقتين'
            }), 400
        
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({
                'success': False,
                'message': message
            }), 400
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({
                    'success': False,
                    'message': 'اسم المستخدم موجود بالفعل'
                }), 400
            else:
                return jsonify({
                    'success': False,
                    'message': 'البريد الإلكتروني موجود بالفعل'
                }), 400
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم إنشاء الحساب بنجاح',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'خطأ في إنشاء الحساب: {str(e)}'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'لم يتم إرسال بيانات'
            }), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not username:
            return jsonify({
                'success': False,
                'message': 'اسم المستخدم مطلوب'
            }), 400
        
        if not password:
            return jsonify({
                'success': False,
                'message': 'كلمة المرور مطلوبة'
            }), 400
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({
                'success': False,
                'message': 'اسم المستخدم أو كلمة المرور غير صحيحة'
            }), 401
        
        if not user.is_active:
            return jsonify({
                'success': False,
                'message': 'الحساب غير مفعل'
            }), 401
        
        # Login user
        login_user(user, remember=remember)
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم تسجيل الدخول بنجاح',
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في تسجيل الدخول: {str(e)}'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    try:
        logout_user()
        return jsonify({
            'success': True,
            'message': 'تم تسجيل الخروج بنجاح'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في تسجيل الخروج: {str(e)}'
        }), 500

@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """Get current user info"""
    try:
        # Check if user is authenticated
        if current_user.is_authenticated:
            return jsonify({
                'success': True,
                'user': current_user.to_dict()
            })
        else:
            return jsonify({
                'success': False,
                'message': 'غير مسجل الدخول'
            }), 401
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ في جلب بيانات المستخدم: {str(e)}'
        }), 500

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'لم يتم إرسال بيانات'
            }), 400
        
        email = data.get('email', '').strip().lower()
        
        if email and email != current_user.email:
            if not validate_email(email):
                return jsonify({
                    'success': False,
                    'message': 'صيغة البريد الإلكتروني غير صحيحة'
                }), 400
            
            # Check if email is already taken
            existing_user = User.query.filter(
                (User.email == email) & (User.id != current_user.id)
            ).first()
            
            if existing_user:
                return jsonify({
                    'success': False,
                    'message': 'البريد الإلكتروني موجود بالفعل'
                }), 400
            
            current_user.email = email
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم تحديث الملف الشخصي بنجاح',
            'user': current_user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'خطأ في تحديث الملف الشخصي: {str(e)}'
        }), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'message': 'لم يتم إرسال بيانات'
            }), 400
        
        current_password = data.get('currentPassword', '')
        new_password = data.get('newPassword', '')
        confirm_password = data.get('confirmPassword', '')
        
        if not current_password:
            return jsonify({
                'success': False,
                'message': 'كلمة المرور الحالية مطلوبة'
            }), 400
        
        if not current_user.check_password(current_password):
            return jsonify({
                'success': False,
                'message': 'كلمة المرور الحالية غير صحيحة'
            }), 400
        
        if not new_password:
            return jsonify({
                'success': False,
                'message': 'كلمة المرور الجديدة مطلوبة'
            }), 400
        
        if new_password != confirm_password:
            return jsonify({
                'success': False,
                'message': 'كلمتا المرور الجديدتان غير متطابقتين'
            }), 400
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return jsonify({
                'success': False,
                'message': message
            }), 400
        
        current_user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم تغيير كلمة المرور بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'خطأ في تغيير كلمة المرور: {str(e)}'
        }), 500
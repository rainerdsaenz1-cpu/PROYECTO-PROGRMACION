"""
Módulo de seguridad: Validación, sanitización y prevención de inyecciones.
"""
import re
from bleach import clean
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================================
# PREVENCIÓN DE XSS
# ============================================================================

def sanitize_input(user_input, allow_html=False):
    """
    Sanitiza la entrada del usuario para prevenir XSS.
    
    Args:
        user_input (str): Entrada del usuario
        allow_html (bool): Si se permite HTML (por defecto False)
    
    Returns:
        str: Entrada sanitizada
    """
    if not isinstance(user_input, str):
        return ""
    
    # Remover espacios en blanco al inicio y final
    user_input = user_input.strip()
    
    if allow_html:
        # Permitir solo etiquetas HTML seguras
        return clean(user_input, 
                     tags={'b', 'i', 'em', 'strong', 'p', 'br', 'a'},
                     attributes={'a': ['href', 'title']})
    else:
        # Remover todas las etiquetas HTML
        return clean(user_input, tags=[], strip=True)


def escape_html(text):
    """
    Escapa caracteres especiales HTML para mostrarlos de forma segura.
    
    Args:
        text (str): Texto a escapar
    
    Returns:
        str: Texto escapado
    """
    if text is None:
        return ""
    
    text = str(text)
    escapes = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    return ''.join(escapes.get(char, char) for char in text)


# ============================================================================
# VALIDACIONES
# ============================================================================

def validate_username(username):
    """
    Valida el nombre de usuario (alfanumérico, 3-20 caracteres).
    
    Args:
        username (str): Nombre de usuario
    
    Returns:
        tuple: (bool, str) - (es_válido, mensaje_error)
    """
    if not username or len(username) < 3 or len(username) > 20:
        return False, "El usuario debe tener entre 3 y 20 caracteres"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "El usuario solo puede contener letras, números, guiones y guiones bajos"
    
    return True, ""


def validate_password(password):
    """
    Valida la contraseña (mínimo 8 caracteres, mayúscula, número, carácter especial).
    
    Args:
        password (str): Contraseña
    
    Returns:
        tuple: (bool, str) - (es_válida, mensaje_error)
    """
    if not password or len(password) < 8:
        return False, "La contraseña debe tener mínimo 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe contener al menos un número"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?]', password):
        return False, "La contraseña debe contener al menos un carácter especial (!@#$%^&*...)"
    
    return True, ""


def validate_email(email):
    """
    Valida el formato del email.
    
    Args:
        email (str): Email
    
    Returns:
        tuple: (bool, str) - (es_válido, mensaje_error)
    """
    # Patrón básico de validación de email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not email or not re.match(pattern, email):
        return False, "El email no es válido"
    
    if len(email) > 120:
        return False, "El email es demasiado largo (máximo 120 caracteres)"
    
    return True, ""


def validate_numeric_field(value, min_value=None, max_value=None):
    """
    Valida que un campo sea numérico dentro del rango especificado.
    
    Args:
        value (str): Valor a validar
        min_value (float): Valor mínimo
        max_value (float): Valor máximo
    
    Returns:
        tuple: (bool, str, float) - (es_válido, mensaje_error, valor_convertido)
    """
    try:
        num_value = float(value)
        
        if min_value is not None and num_value < min_value:
            return False, f"El valor debe ser mayor o igual a {min_value}", None
        
        if max_value is not None and num_value > max_value:
            return False, f"El valor debe ser menor o igual a {max_value}", None
        
        return True, "", num_value
    except (ValueError, TypeError):
        return False, "El valor debe ser un número", None


def validate_text_field(text, min_length=1, max_length=255, allow_special=True):
    """
    Valida un campo de texto.
    
    Args:
        text (str): Texto a validar
        min_length (int): Longitud mínima
        max_length (int): Longitud máxima
        allow_special (bool): Permitir caracteres especiales
    
    Returns:
        tuple: (bool, str) - (es_válido, mensaje_error)
    """
    if not text or len(text) < min_length or len(text) > max_length:
        return False, f"El campo debe tener entre {min_length} y {max_length} caracteres"
    
    if not allow_special and not re.match(r'^[a-zA-Z0-9\s]+$', text):
        return False, "El campo contiene caracteres no permitidos"
    
    return True, ""


# ============================================================================
# PREVENCIÓN DE INYECCIÓN NoSQL
# ============================================================================

def sanitize_mongo_query(query_value):
    """
    Sanitiza valores para prevenir inyección NoSQL.
    Rechaza operadores especiales de MongoDB.
    
    Args:
        query_value (str): Valor a sanitizar
    
    Returns:
        str: Valor sanitizado
    """
    if not isinstance(query_value, str):
        return ""
    
    query_value = query_value.strip()
    
    # Patrones peligrosos de MongoDB
    dangerous_patterns = [
        r'\$ne',
        r'\$or',
        r'\$and',
        r'\$gt',
        r'\$gte',
        r'\$lt',
        r'\$lte',
        r'\$in',
        r'\$nin',
        r'\$exists',
        r'\$regex',
        r'\$where',
        r'\$json',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, query_value, re.IGNORECASE):
            return ""  # Rechazar si contiene operadores peligrosos
    
    # Rechazar si contiene caracteres JSON potencialmente peligrosos
    if query_value.startswith('{') or query_value.startswith('['):
        return ""
    
    return query_value


def validate_mongo_id(mongo_id):
    """
    Valida que un ID sea seguro para usar en consultas MongoDB.
    
    Args:
        mongo_id: ID a validar
    
    Returns:
        tuple: (bool, str) - (es_válido, ID_sanitizado)
    """
    if not mongo_id:
        return False, None
    
    # Convertir a string y sanitizar
    mongo_id = str(mongo_id).strip()
    
    # Rechazar patrones peligrosos
    if not mongo_id or sanitize_mongo_query(mongo_id) == "":
        return False, None
    
    return True, mongo_id


# ============================================================================
# HASH DE CONTRASEÑAS
# ============================================================================

def hash_password(password):
    """
    Genera un hash seguro de la contraseña.
    
    Args:
        password (str): Contraseña en texto plano
    
    Returns:
        str: Hash de la contraseña
    """
    return generate_password_hash(password, method='pbkdf2:sha256')


def verify_password(password, password_hash):
    """
    Verifica que una contraseña coincida con su hash.
    
    Args:
        password (str): Contraseña en texto plano
        password_hash (str): Hash de la contraseña
    
    Returns:
        bool: True si coinciden, False en caso contrario
    """
    return check_password_hash(password_hash, password)


# ============================================================================
# VALIDACIÓN DE ROLES
# ============================================================================

VALID_ROLES = ['operador', 'administrador']


def validate_role(role):
    """
    Valida que el rol sea uno de los permitidos.
    
    Args:
        role (str): Rol a validar
    
    Returns:
        bool: True si es válido, False en caso contrario
    """
    return role in VALID_ROLES


def is_admin(role):
    """
    Comprueba si el rol es administrador.
    
    Args:
        role (str): Rol a verificar
    
    Returns:
        bool: True si es administrador
    """
    return role == 'administrador'


def is_operator(role):
    """
    Comprueba si el rol es operador.
    
    Args:
        role (str): Rol a verificar
    
    Returns:
        bool: True si es operador
    """
    return role == 'operador'

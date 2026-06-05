
"""
============Banco Seguro - Aplicación Flask con Seguridad Mejorada============
Aplicación Flask Segura con Autenticación y Roles
Implementa: Prevención XSS, Inyección NoSQL, Sistema de Login con Roles.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import CSRFProtect
from pymongo import MongoClient
from functools import wraps
from datetime import datetime
from bson.objectid import ObjectId
import os

from security import (
    sanitize_input, escape_html, 
    validate_username, validate_password, validate_email, validate_text_field,
    validate_numeric_field, sanitize_mongo_query, validate_mongo_id,
    hash_password, verify_password, validate_role, is_admin, is_operator
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
# Activar protección CSRF en formularios POST
csrf = CSRFProtect(app)

# ============================================================================
# CONEXIÓN A BASE DE DATOS
# ============================================================================

client = MongoClient('mongodb://admin:123456@localhost:27017/')
db = client['banco_seguro']
usuarios_col = db['usuarios']
transacciones_col = db['transacciones']

# Crear índices para optimizar búsquedas
usuarios_col.create_index('username', unique=True)
usuarios_col.create_index('email', unique=True)
# Índices para filtros de estado (mejor rendimiento)
usuarios_col.create_index('activo')
transacciones_col.create_index('eliminada')

# ============================================================================
# DECORADORES PARA CONTROL DE ACCESO
# ============================================================================

def login_required(f):
    """Verifica que el usuario esté autenticado."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role):
    """Verifica que el usuario tenga el rol requerido."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'usuario_id' not in session:
                flash('Por favor, inicia sesión primero.', 'warning')
                return redirect(url_for('login'))
            
            try:
                usuario = usuarios_col.find_one({'_id': ObjectId(session['usuario_id'])})
            except Exception:
                session.clear()
                flash('Sesión inválida. Por favor, inicia sesión de nuevo.', 'warning')
                return redirect(url_for('login'))

            if not usuario or usuario.get('rol') != required_role:
                flash(f'Acceso denegado. Se requiere rol: {required_role}', 'danger')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Verifica que el usuario sea administrador."""
    return role_required('administrador')(f)


def operator_required(f):
    """Verifica que el usuario sea operador."""
    return role_required('operador')(f)


# ============================================================================
# RUTAS DE AUTENTICACIÓN
# ============================================================================

@app.route('/')
def index():
    """Página de inicio. Redirige a login si no está autenticado."""
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Formulario y procesamiento de login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validar que los campos no estén vacíos
        if not username or not password:
            flash('Usuario y contraseña son requeridos.', 'danger')
            return redirect(url_for('login'))
        
        # Sanitizar username para prevenir NoSQL injection
        username_sanitized = sanitize_mongo_query(username)
        if not username_sanitized:
            flash('Usuario no válido.', 'danger')
            return redirect(url_for('login'))
        
        # Buscar el usuario en la base de datos (solo activos)
        usuario = usuarios_col.find_one({'username': username_sanitized, 'activo': True})
        
        if usuario and verify_password(password, usuario['password_hash']):
            # Login exitoso
            session['usuario_id'] = str(usuario['_id'])
            session['usuario_nombre'] = usuario['username']
            session['usuario_rol'] = usuario['rol']
            
            flash(f'¡Bienvenido, {usuario["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Login fallido
            flash('Usuario o contraseña incorrectos.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Formulario y procesamiento de registro de usuarios."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        email = request.form.get('email', '').strip()
        rol = 'operador'

        def render_register_form():
            return render_template('register.html', old_username=username, old_email=email)
        
        # ===== VALIDACIONES =====
        
        # Validar username
        is_valid, msg = validate_username(username)
        if not is_valid:
            flash(msg, 'danger')
            return render_register_form()
        
        # Validar email
        is_valid, msg = validate_email(email)
        if not is_valid:
            flash(msg, 'danger')
            return render_register_form()
        
        # Validar contraseña
        if password != password_confirm:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_register_form()
        
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return render_register_form()
        
        # ===== VERIFICAR EXISTENCIA =====

        usuario_activo = usuarios_col.find_one({'username': username, 'activo': True})
        if usuario_activo:
            flash('El usuario ya existe.', 'danger')
            return render_register_form()

        email_activo = usuarios_col.find_one({'email': email, 'activo': True})
        if email_activo:
            flash('El email ya está registrado.', 'danger')
            return render_register_form()

        usuario_inactivo = usuarios_col.find_one({'username': username, 'activo': False})
        email_inactivo = usuarios_col.find_one({'email': email, 'activo': False})

        if usuario_inactivo and email_inactivo and usuario_inactivo['_id'] != email_inactivo['_id']:
            flash('Ya existe un usuario eliminado con ese nombre o email.', 'danger')
            return render_register_form()

        if usuario_inactivo:
            usuarios_col.update_one(
                {'_id': usuario_inactivo['_id']},
                {'$set': {
                    'email': email,
                    'password_hash': hash_password(password),
                    'rol': rol,
                    'activo': True,
                    'fecha_reactivacion': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }}
            )
            flash('Cuenta reactivada correctamente. Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))

        if email_inactivo:
            usuarios_col.update_one(
                {'_id': email_inactivo['_id']},
                {'$set': {
                    'username': username,
                    'password_hash': hash_password(password),
                    'rol': rol,
                    'activo': True,
                    'fecha_reactivacion': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }}
            )
            flash('Cuenta reactivada correctamente. Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))
        
        # ===== CREAR USUARIO =====
        
        nuevo_usuario = {
            'username': username,
            'email': email,
            'password_hash': hash_password(password),
            'rol': rol,
            'fecha_creacion': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'activo': True
        }
        
        resultado = usuarios_col.insert_one(nuevo_usuario)
        
        flash('¡Registro exitoso! Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Cierra la sesión del usuario."""
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))


# ============================================================================
# DASHBOARD PRINCIPAL
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Panel de control según el rol del usuario."""
    usuario_rol = session.get('usuario_rol')
    usuario_nombre = session.get('usuario_nombre')
    
    if is_admin(usuario_rol):
        return render_template('dashboard.html', 
                               usuario_nombre=usuario_nombre,
                               usuario_rol=usuario_rol,
                               es_admin=True)
    elif is_operator(usuario_rol):
        return render_template('dashboard.html',
                               usuario_nombre=usuario_nombre,
                               usuario_rol=usuario_rol,
                               es_admin=False)
    else:
        flash('Rol no reconocido.', 'danger')
        return redirect(url_for('logout'))


# ============================================================================
# OPERADOR: INGRESAR TRANSACCIONES
# ============================================================================

@app.route('/operador', methods=['GET', 'POST'])
@operator_required
def operador():
    """Panel del operador para ingresar transacciones."""
    mensaje = ""
    tipo_mensaje = ""
    
    if request.method == 'POST':
        # ===== VALIDACIONES =====
        
        # Validar ID
        id_cliente = request.form.get('id', '').strip()
        is_valid, msg = validate_text_field(id_cliente, min_length=1, max_length=24, allow_special=False)
        if not is_valid:
            flash(f'ID: {msg}', 'danger')
            return redirect(url_for('operador'))
        
        # Sanitizar para prevenir NoSQL injection
        id_cliente = sanitize_mongo_query(id_cliente)
        if not id_cliente:
            flash('ID contiene caracteres no permitidos.', 'danger')
            return redirect(url_for('operador'))
        
        # Validar nombre
        nombre = sanitize_input(request.form.get('nombre', '').strip())
        is_valid, msg = validate_text_field(nombre, min_length=1, max_length=20)
        if not is_valid:
            flash(f'Nombre: {msg}', 'danger')
            return redirect(url_for('operador'))
        
        # Validar apellido
        apellido = sanitize_input(request.form.get('apellido', '').strip())
        is_valid, msg = validate_text_field(apellido, min_length=1, max_length=20)
        if not is_valid:
            flash(f'Apellido: {msg}', 'danger')
            return redirect(url_for('operador'))
        
        # Validar tipo de transacción (usar lista de valores permitidos)
        tipos_permitidos = ['pago', 'crédito']
        tipo = request.form.get('tipo', '').strip()
        if tipo not in tipos_permitidos:
            flash(f'Tipo de transacción no válido. Permitidos: {", ".join(tipos_permitidos)}', 'danger')
            return redirect(url_for('operador'))
        
        # Validar valor
        valor = request.form.get('valor', '').strip()
        is_valid, msg, valor_numerico = validate_numeric_field(valor, min_value=0.01, max_value=999999.99)
        if not is_valid:
            flash(f'Valor: {msg}', 'danger')
            return redirect(url_for('operador'))
        
        # ===== INSERTAR TRANSACCIÓN =====
        
        datos = {
            "id": id_cliente,
            "nombre": nombre,
            "apellido": apellido,
            "tipo": tipo,
            "valor": valor_numerico,
            "usuario_creador": session.get('usuario_nombre'),
            "fecha_hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "eliminada": False
        }
        
        transacciones_col.insert_one(datos)
        mensaje = f"✅ Transacción registrada correctamente"
        tipo_mensaje = "success"
    
    return render_template('operador.html', 
                           mensaje=mensaje,
                           tipo_mensaje=tipo_mensaje,
                           usuario_nombre=session.get('usuario_nombre'))


# ============================================================================
# ADMIN: VER, BUSCAR, MODIFICAR, ELIMINAR TRANSACCIONES
# ============================================================================

@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    """Panel del administrador para ver y gestionar transacciones."""
    
    id_buscar = request.args.get('id', '').strip()
    registros = []
    
    if id_buscar:
        # Sanitizar para prevenir NoSQL injection
        id_sanitizado = sanitize_mongo_query(id_buscar)
        
        if id_sanitizado:
            # Usar búsqueda exacta en lugar de REGEX por seguridad (solo activas)
            registros = list(transacciones_col.find({"id": id_sanitizado, "eliminada": False}))
        # Si no es válido, mostrar lista vacía
    else:
        # Mostrar todas las transacciones activas
        registros = list(transacciones_col.find({"eliminada": False}))
    
    # Convertir ObjectId a string para mostrar en la plantilla
    for reg in registros:
        reg['_id'] = str(reg['_id'])
    
    return render_template('admin.html',
                           registros=registros,
                           busqueda=escape_html(id_buscar),
                           usuario_nombre=session.get('usuario_nombre'))


@app.route('/editar/<id_transaccion>', methods=['GET', 'POST'])
@admin_required
def editar(id_transaccion):
    """Editar una transacción (solo administrador)."""
    
    # Validar que el ID sea una ObjectId válida
    try:
        from bson.objectid import ObjectId
        objeto_id = ObjectId(id_transaccion)
    except:
        flash('ID de transacción no válido.', 'danger')
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        # ===== VALIDACIONES =====
        
        nombre = sanitize_input(request.form.get('nombre', '').strip())
        is_valid, msg = validate_text_field(nombre, min_length=1, max_length=20)
        if not is_valid:
            flash(f'Nombre: {msg}', 'danger')
            return redirect(url_for('editar', id_transaccion=id_transaccion))
        
        apellido = sanitize_input(request.form.get('apellido', '').strip())
        is_valid, msg = validate_text_field(apellido, min_length=1, max_length=20)
        if not is_valid:
            flash(f'Apellido: {msg}', 'danger')
            return redirect(url_for('editar', id_transaccion=id_transaccion))
        
        tipos_permitidos = ['pago', 'crédito']
        tipo = request.form.get('tipo', '').strip()
        if tipo not in tipos_permitidos:
            flash('Tipo de transacción no válido.', 'danger')
            return redirect(url_for('editar', id_transaccion=id_transaccion))
        
        valor = request.form.get('valor', '').strip()
        is_valid, msg, valor_numerico = validate_numeric_field(valor, min_value=0.01, max_value=999999.99)
        if not is_valid:
            flash(f'Valor: {msg}', 'danger')
            return redirect(url_for('editar', id_transaccion=id_transaccion))
        
        # ===== ACTUALIZAR TRANSACCIÓN =====
        
        nuevos_datos = {
            "nombre": nombre,
            "apellido": apellido,
            "tipo": tipo,
            "valor": valor_numerico,
            "usuario_modificador": session.get('usuario_nombre'),
            "fecha_modificacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        transacciones_col.update_one(
            {"_id": objeto_id},
            {"$set": nuevos_datos}
        )
        
        flash('✅ Transacción actualizada correctamente', 'success')
        return redirect(url_for('admin'))
    
    # GET: Mostrar formulario de edición
    registro = transacciones_col.find_one({"_id": objeto_id, "eliminada": False})
    
    if not registro:
        flash('Transacción no encontrada.', 'danger')
        return redirect(url_for('admin'))

    # Bloquear edición si el usuario creador fue eliminado
    if registro.get('usuario_creador') == '[usuario eliminado]':
        flash('No se puede editar una transacción de un usuario eliminado.', 'warning')
        return redirect(url_for('admin'))
    
    return render_template('editar.html',
                           registro=registro,
                           usuario_nombre=session.get('usuario_nombre'))


@app.route('/eliminar/<id_transaccion>', methods=['POST'])
@admin_required
def eliminar(id_transaccion):
    """Desactivar una transacción (soft delete) (solo administrador)."""
    
    # Validar que el ID sea una ObjectId válida
    try:
        from bson.objectid import ObjectId
        objeto_id = ObjectId(id_transaccion)
    except:
        flash('ID de transacción no válido.', 'danger')
        return redirect(url_for('admin'))
    
    # SOFT DELETE: marcar como eliminada
    resultado = transacciones_col.update_one(
        {"_id": objeto_id},
        {"$set": {"eliminada": True, "fecha_eliminacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "usuario_eliminador": session.get('usuario_nombre')}}
    )
    
    if resultado.modified_count > 0:
        flash('✅ Transacción desactivada correctamente', 'success')
    else:
        flash('Transacción no encontrada.', 'warning')
    
    return redirect(url_for('admin'))


# ============================================================================
# GESTIÓN DE USUARIOS (Solo admin)
# ============================================================================

@app.route('/usuarios')
@admin_required
def usuarios():
    """Listar todos los usuarios activos (solo administrador)."""
    
    lista_usuarios = list(usuarios_col.find({'activo': True}, {
        '_id': 1,
        'username': 1,
        'email': 1,
        'rol': 1,
        'fecha_creacion': 1,
        'activo': 1
    }))
    
    # Convertir ObjectId a string
    for user in lista_usuarios:
        user['_id'] = str(user['_id'])
    
    return render_template('usuarios.html',
                           usuarios=lista_usuarios,
                           usuario_nombre=session.get('usuario_nombre'))


@app.route('/eliminar-usuario/<id_usuario>', methods=['POST'])
@admin_required
def eliminar_usuario(id_usuario):
    """Desactivar un usuario (soft delete) (solo administrador)."""
    
    try:
        from bson.objectid import ObjectId
        objeto_id = ObjectId(id_usuario)
    except:
        flash('ID de usuario no válido.', 'danger')
        return redirect(url_for('usuarios'))
    
    # No permitir desactivarse a sí mismo
    if str(objeto_id) == str(session.get('usuario_id')):
        flash('No puedes desactivar tu propia cuenta.', 'warning')
        return redirect(url_for('usuarios'))
    
    # Obtener usuario antes de desactivar (para anonimizar transacciones)
    usuario_a_eliminar = usuarios_col.find_one({"_id": objeto_id})
    if not usuario_a_eliminar:
        flash('Usuario no encontrado.', 'warning')
        return redirect(url_for('usuarios'))
    
    # SOFT DELETE: marcar como inactivo
    resultado = usuarios_col.update_one(
        {"_id": objeto_id},
        {"$set": {"activo": False, "fecha_desactivacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}}
    )
    
    # Anonimizar transacciones del usuario
    if resultado.modified_count > 0:
        transacciones_col.update_many(
            {"usuario_creador": usuario_a_eliminar['username']},
            {"$set": {"usuario_creador": "[usuario eliminado]"}}
        )
        flash('Usuario desactivado correctamente.', 'success')
    else:
        flash('No se pudo desactivar el usuario.', 'warning')
    
    return redirect(url_for('usuarios'))


# ============================================================================
# MANEJO DE ERRORES
# ============================================================================

@app.errorhandler(404)
def pagina_no_encontrada(error):
    """Maneja errores 404."""
    return render_template('error.html', 
                           codigo_error=404,
                           mensaje='Página no encontrada'), 404


@app.errorhandler(500)
def error_servidor(error):
    """Maneja errores 500."""
    return render_template('error.html',
                           codigo_error=500,
                           mensaje='Error interno del servidor'), 500


@app.errorhandler(403)
def acceso_denegado(error):
    """Maneja errores 403."""
    return render_template('error.html',
                           codigo_error=403,
                           mensaje='Acceso denegado'), 403


# ============================================================================
# INICIAR APLICACIÓN
# ============================================================================

if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5000)

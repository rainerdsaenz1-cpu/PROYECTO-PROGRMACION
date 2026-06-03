"""
Script de inicialización para crear usuarios demo en la base de datos.
Ejecutar una sola vez: python init_db.py
"""

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from security import hash_password
from datetime import datetime

# Conexión a MongoDB
client = MongoClient('mongodb://admin:123456@localhost:27017/')
db = client['banco_seguro']
usuarios_col = db['usuarios']

# Crear índices
usuarios_col.create_index('username', unique=True)
usuarios_col.create_index('email', unique=True)

# Usuarios demo
usuarios_demo = [
    {
        'username': 'admin',
        'email': 'admin@banco.com',
        'password_hash': hash_password('Admin@123'),
        'rol': 'administrador',
        'fecha_creacion': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'activo': True
    },
    {
        'username': 'operador',
        'email': 'operador@banco.com',
        'password_hash': hash_password('Operador@123'),
        'rol': 'operador',
        'fecha_creacion': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'activo': True
    }
]

# Limpiar usuarios existentes (opcional)
# usuarios_col.delete_many({})
# print("✅ Base de datos limpiada")

# Insertar usuarios (intento por usuario para aislar errores)
for usuario in usuarios_demo:
    try:
        resultado = usuarios_col.insert_one(usuario)
        print(f"✅ Usuario '{usuario['username']}' creado exitosamente")
        print(f"   - Email: {usuario['email']}")
        print(f"   - Rol: {usuario['rol']}")
        print(f"   - ID: {resultado.inserted_id}")
    except DuplicateKeyError:
        print(f"⚠️ Usuario '{usuario['username']}' ya existe (clave duplicada)")
    except Exception as e:
        print(f"⚠️ Error al crear '{usuario['username']}': {e}")

print("\n" + "="*60)
print("🏦 BANCO SEGURO - Usuarios Demo Inicializados")
print("="*60)
print("\nCredenciales para prueba:")
print("\n👤 ADMINISTRADOR:")
print("   Usuario: admin")
print("   Contraseña: Admin@123")
print("   Permisos: Ver, modificar, eliminar transacciones + gestión de usuarios")
print("\n👤 OPERADOR:")
print("   Usuario: operador")
print("   Contraseña: Operador@123")
print("   Permisos: Ingresar transacciones")
print("\n" + "="*60)

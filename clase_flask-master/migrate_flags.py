"""
Script de migración para normalizar flags en la base de datos:
- Establece `activo: True` en usuarios si no existe
- Establece `eliminada: False` en transacciones si no existe

Ejecutar: python migrate_flags.py
"""
from pymongo import MongoClient

client = MongoClient('mongodb://admin:123456@localhost:27017/')
db = client['banco_seguro']
usuarios_col = db['usuarios']
transacciones_col = db['transacciones']

# Usuarios: activar por defecto si falta campo
res_u = usuarios_col.update_many({'activo': {'$exists': False}}, {'$set': {'activo': True}})
print(f"Usuarios actualizados (activo agregado): {res_u.modified_count}")

# Transacciones: marcar como no eliminadas si falta campo
res_t = transacciones_col.update_many({'eliminada': {'$exists': False}}, {'$set': {'eliminada': False}})
print(f"Transacciones actualizadas (eliminada agregado): {res_t.modified_count}")

print("Migración completa. Revisa los contadores y correbacks si es necesario.")

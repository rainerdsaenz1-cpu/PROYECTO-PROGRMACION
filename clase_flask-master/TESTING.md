# 🧪 GUÍA DE PRUEBAS - Banco Seguro

## ✅ Verificación Rápida del Sistema

### 1. Verificar que todo está ejecutándose

```powershell
# Terminal 1: MongoDB
docker compose up -d
docker ps  # Debe mostrar mongo y mongo-express

# Terminal 2: Flask
python app.py
# Debe mostrar: "Running on http://0.0.0.0:5000"
```

### 2. Acceder a la aplicación

- **URL**: http://localhost:5000
- **Debe redirigir a**: http://localhost:5000/login

---

## 🔑 PRUEBAS DE AUTENTICACIÓN

### Caso 1: Login Correcto (Admin)
```
1. Ir a /login
2. Usuario: admin
3. Contraseña: Admin@123
4. Click "Iniciar Sesión"
✅ ESPERADO: Redirige a /dashboard (Panel Admin)
```

### Caso 2: Login Correcto (Operador)
```
1. Ir a /login
2. Usuario: operador
3. Contraseña: Operador@123
4. Click "Iniciar Sesión"
✅ ESPERADO: Redirige a /dashboard (Panel Operador)
```

### Caso 3: Login Incorrecto
```
1. Ir a /login
2. Usuario: admin
3. Contraseña: IncorrectPassword
4. Click "Iniciar Sesión"
✅ ESPERADO: Mensaje "Usuario o contraseña incorrectos"
```

### Caso 4: Login Vacío
```
1. Ir a /login
2. Dejar campos vacíos
3. Click "Iniciar Sesión"
✅ ESPERADO: Mensaje "Usuario y contraseña son requeridos"
```

### Caso 5: Cerrar Sesión
```
1. Estar logueado
2. Click en "Cerrar sesión" (navbar)
✅ ESPERADO: Redirige a /login con mensaje "Has cerrado sesión"
```

---

## 📝 PRUEBAS DE REGISTRO

### Caso 6: Registro Válido
```
1. Ir a /register
2. Usuario: usuario_nuevo
3. Email: nuevo@example.com
4. Contraseña: NewPass@123
5. Confirmar: NewPass@123
6. Rol: Operador
7. Click "Crear Cuenta"
✅ ESPERADO: Redirige a /login con "Registro exitoso"
✅ Luego puede iniciar sesión con ese usuario
```

### Caso 7: Usuario Duplicado
```
1. Ir a /register
2. Usuario: admin (ya existe)
3. Email: admin2@example.com
4. Contraseña: Admin@123
5. Rol: Operador
6. Click "Crear Cuenta"
✅ ESPERADO: Mensaje "El usuario ya existe"
```

### Caso 8: Email Duplicado
```
1. Ir a /register
2. Usuario: otro_usuario
3. Email: admin@banco.com (ya existe)
4. Contraseña: Admin@123
5. Rol: Operador
6. Click "Crear Cuenta"
✅ ESPERADO: Mensaje "El email ya está registrado"
```

### Caso 9: Contraseña Débil
```
1. Ir a /register
2. Usuario: test_user
3. Email: test@example.com
4. Contraseña: pass123 (sin mayúscula, sin especial)
5. Confirmar: pass123
6. Rol: Operador
7. Click "Crear Cuenta"
✅ ESPERADO: Error "La contraseña debe contener..."
```

### Caso 10: Contraseñas No Coinciden
```
1. Ir a /register
2. Usuario: test_user
3. Email: test@example.com
4. Contraseña: NewPass@123
5. Confirmar: DifferentPass@123
6. Rol: Operador
7. Click "Crear Cuenta"
✅ ESPERADO: Mensaje "Las contraseñas no coinciden"
```

---

## 💳 PRUEBAS DE OPERADOR (Crear Transacciones)

### Caso 11: Crear Transacción Válida
```
1. Loguearse como: operador / Operador@123
2. Ir a Panel Operador
3. ID: CLI001
4. Nombre: Juan
5. Apellido: Pérez
6. Tipo: pago
7. Valor: 1500.50
8. Click "Guardar Transacción"
✅ ESPERADO: Mensaje verde "Transacción registrada"
```

### Caso 12: Transacción Sin ID
```
1. Loguearse como operador
2. Dejar ID vacío
3. Completar otros campos
4. Click "Guardar Transacción"
✅ ESPERADO: Validación HTML5 (navegador pide ID)
```

### Caso 13: Valor Negativo
```
1. Loguearse como operador
2. ID: CLI002
3. Valor: -100
4. Click "Guardar Transacción"
✅ ESPERADO: Error "El valor debe ser mayor o igual a 0.01"
```

### Caso 14: Valor Muy Grande
```
1. Loguearse como operador
2. Valor: 9999999.99
3. Click "Guardar Transacción"
✅ ESPERADO: Error "El valor debe ser menor o igual a 999,999.99"
```

---

## 🛡️ PRUEBAS DE SEGURIDAD - XSS

### Caso 15: XSS en Nombre
```
1. Loguearse como operador
2. ID: CLI_XSS
3. Nombre: <script>alert('XSS')</script>
4. Valor: 100
5. Click "Guardar Transacción"
✅ ESPERADO: Se guarda
6. Loguearse como admin
7. Ir a /admin
8. Ver transacción con nombre
✅ ESPERADO: Se ve como texto: "&lt;script&gt;alert(...)"
✅ NO ejecuta alert
```

### Caso 16: XSS con IMG Tag
```
1. Nombre: Juan<img src=x onerror="alert('XSS')">
2. Similar al caso 15
✅ ESPERADO: Se sanitiza, no ejecuta
```

### Caso 17: XSS en Campo de Búsqueda (Admin)
```
1. Loguearse como admin
2. Ir a /admin
3. Campo Buscar: <script>alert('XSS')</script>
4. Click Buscar
✅ ESPERADO: Se muestra como texto en la página
✅ NO ejecuta alert
```

---

## 🚫 PRUEBAS DE SEGURIDAD - NoSQL Injection

### Caso 18: NoSQL Injection - $ne
```
1. Loguearse como admin
2. Ir a /admin
3. Campo Buscar: {"$ne": ""}
4. Click Buscar
✅ ESPERADO: No devuelve nada (lista vacía)
✅ NO devuelve todas las transacciones
```

### Caso 19: NoSQL Injection - $or
```
1. Campo Buscar: {"$or": [{"admin": true}]}
2. Click Buscar
✅ ESPERADO: Rechaza por contener operador peligroso
✅ Lista vacía, no ejecuta $or
```

### Caso 20: NoSQL Injection - JSON Injection
```
1. Campo Buscar: [{"id": "CLI001"}]
2. Click Buscar
✅ ESPERADO: Rechaza por comienza con [
✅ Lista vacía
```

---

## 👥 PRUEBAS DE CONTROL DE ACCESO

### Caso 21: Operador Intenta Acceder a /admin
```
1. Loguearse como operador
2. Navegar a: http://localhost:5000/admin
✅ ESPERADO: Redirige a /dashboard
✅ Mensaje: "Acceso denegado. Se requiere rol: administrador"
```

### Caso 22: Operador Intenta Acceder a /usuarios
```
1. Loguearse como operador
2. Navegar a: http://localhost:5000/usuarios
✅ ESPERADO: Redirige a /dashboard con error de acceso
```

### Caso 23: Admin Puede Acceder a /admin
```
1. Loguearse como admin
2. Navegar a: http://localhost:5000/admin
✅ ESPERADO: Acceso permitido, ve la tabla de transacciones
```

### Caso 24: Admin Puede Acceder a /usuarios
```
1. Loguearse como admin
2. Navegar a: http://localhost:5000/usuarios
✅ ESPERADO: Acceso permitido, ve lista de usuarios
```

### Caso 25: No Autenticado Accede a Ruta Protegida
```
1. Abrir navegador privado
2. Navegar a: http://localhost:5000/admin
✅ ESPERADO: Redirige a /login
✅ Mensaje: "Por favor, inicia sesión primero"
```

---

## 📊 PRUEBAS DE ADMIN - Gestión de Transacciones

### Caso 26: Admin Ve Todas las Transacciones
```
1. Loguearse como admin
2. Ir a /admin
✅ ESPERADO: Muestra tabla con todas las transacciones
```

### Caso 27: Admin Busca por ID
```
1. Loguearse como admin
2. Ir a /admin
3. Buscar: CLI001
4. Click Buscar
✅ ESPERADO: Muestra solo transacciones con ID=CLI001
```

### Caso 28: Admin Edita Transacción
```
1. Loguearse como admin
2. Ir a /admin
3. Click "Editar" en una transacción
4. Cambiar nombre a "Carlos"
5. Click "Guardar Cambios"
✅ ESPERADO: Transacción actualizada
✅ Mensaje: "Transacción actualizada correctamente"
```

### Caso 29: Admin Elimina Transacción
```
1. Loguearse como admin
2. Ir a /admin
3. Click "Eliminar" en una transacción
4. Confirmar en el popup
✅ ESPERADO: Transacción eliminada
✅ Mensaje: "Transacción eliminada correctamente"
```

### Caso 30: Admin Cancela Eliminación
```
1. Loguearse como admin
2. Ir a /admin
3. Click "Eliminar"
4. Click "Cancelar" en el popup
✅ ESPERADO: Transacción NO se elimina
```

---

## 👥 PRUEBAS DE ADMIN - Gestión de Usuarios

### Caso 31: Admin Ve Lista de Usuarios
```
1. Loguearse como admin
2. Ir a /usuarios
✅ ESPERADO: Muestra tabla con todos los usuarios
```

### Caso 32: Admin Elimina Usuario
```
1. Loguearse como admin
2. Ir a /usuarios
3. Buscar usuario: "operador"
4. Click "Eliminar"
5. Confirmar
✅ ESPERADO: Usuario eliminado de la lista
```

### Caso 33: Admin NO Puede Eliminarse a Sí Mismo
```
1. Loguearse como admin
2. Ir a /usuarios
3. Buscar su propio usuario: "admin"
4. El botón "Eliminar" NO debe aparecer
✅ ESPERADO: Botón dice "No disponible" (deshabilitado)
```

---

## 🧪 SUITE DE PRUEBAS AUTOMÁTICA

```powershell
python test_security.py
```

Esto prueba automáticamente:
- ✅ Protección XSS (4 casos)
- ✅ Protección NoSQL (8 casos)
- ✅ Sanitización (2 casos)
- ✅ Validación (20 casos)
- ✅ Escenarios realistas (4 casos)

**Resultado esperado**: ✅ TODAS LAS PRUEBAS PASAN

---

## 📋 CHECKLIST DE VERIFICACIÓN

### Seguridad
- [ ] XSS: Tags HTML se escapan
- [ ] NoSQL: Operadores $ se rechazan
- [ ] Auth: Login y roles funcionan
- [ ] Access: Control por rol activo
- [ ] Audit: Se registran cambios

### Funcionalidad
- [ ] Operador puede crear transacciones
- [ ] Admin puede ver/editar/eliminar
- [ ] Admin puede gestionar usuarios
- [ ] Búsqueda funciona
- [ ] Logout funciona

### Interfaz
- [ ] Navbar se muestra correctamente
- [ ] Mensajes flash aparecen
- [ ] Formularios validan HTML5
- [ ] Tabla se muestra bien
- [ ] Responsive en móvil

### Errores
- [ ] 404 muestra página de error
- [ ] 403 muestra acceso denegado
- [ ] 500 se maneja correctamente
- [ ] No hay errores en consola

---

## 🐛 Troubleshooting

### Problema: "No puedo iniciar sesión"
```
Soluciones:
1. Verificar que MongoDB está corriendo: docker ps
2. Ejecutar: python init_db.py
3. Revisar credenciales exactas: admin / Admin@123
```

### Problema: "La página dice 'Página no encontrada'"
```
Soluciones:
1. Verificar que Flask está corriendo: python app.py
2. URL correcta: http://localhost:5000
3. No http://localhost:5000/app
```

### Problema: "Error de conexión a MongoDB"
```
Soluciones:
1. docker compose up -d
2. docker ps  (debe mostrar mongo)
3. Verificar puerto: 27017
```

### Problema: "Puedo acceder a rutas sin login"
```
Soluciones:
1. Limpiar cookies/cache del navegador
2. Usar navegador privado
3. Revisar que @login_required está en la ruta
```

---

## 📞 Contacto y Ayuda

Si encuentras problemas:
1. Revisa [SEGURIDAD.md](SEGURIDAD.md)
2. Revisa [readme.md](readme.md)
3. Ejecuta: python test_security.py
4. Revisa logs de Flask (terminal)
5. Verifica MongoDB: docker logs mongo

---



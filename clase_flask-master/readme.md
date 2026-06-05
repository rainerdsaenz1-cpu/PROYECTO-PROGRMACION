======Banco seguro======
#Requisitos previos:
- Docker Desktop
- Python 3.8+
- Git

#Pasos de instalación:
1. Abrir Docker Desktop
2. Clonar o descargar el proyecto:
   url repositorio git: https://github.com/rainerdsaenz1-cpu/PROYECTO-PROGRMACION
   Code → Download ZIP
3. Crear entorno virtual(Terminal):
   ```
   python -m venv venv
   .\venv\Scripts\activate.ps1
   # Si falla por permisos:
   # Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Instalar las dependencias correspondientes (Terminal):
   ```
   pip install -r requirements.txt
   ```
5. Iniciar MongoDB con Docker(Terminal):
   ```
   docker compose up -d
   ```
6. Inicializar los usuarios demo en la base de datos (primera vez):
   ```(Terminal)
   python init_db.py
   # Si falla: (ejecute powershell como administrador y adjunte estos comandos):
   # net stop MongoDB
   # docker start mongo_clase 
   # luego vuelva al proyecto y con el venv activo ejecute el comando nuevamente: 
   python init_db.py.
   ```
7. Ejecutar la aplicación (Terminal):
   ```
   python app.py
   ```
8. Acceder en el navegador:
   - URL: `http://localhost:5000` o `http://192.168.1.6:5000`
9. Login por credenciales Demo:
   - Usuario Admin: `admin` / `Admin@123`
   - Usuario Operador: `operador` / `Operador@123`
10. Login con registro previo
- Registrese con las credenciales correspondientes, su rol será automaticamente (Operador).
- Ingrese las credenciales registradas en el login.
9. Detener la aplicación (Terminal):
   ```
   Ctrl + C
   deactivate
   docker compose down
   ```


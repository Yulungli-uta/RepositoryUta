# Implementación del Cliente WebSocket en React

## 🎯 Objetivo
Conectar una aplicación React al backend de notificaciones híbridas usando SignalR para recibir notificaciones de login de Office365 en tiempo real.

## 📦 Instalación de Dependencias

```bash
npm install @microsoft/signalr
```

## 🔌 Hook de React para WebSocket

Este hook reutilizable maneja la conexión, reconexión, eventos y estado del WebSocket.

```javascript
// hooks/useNotificationWebSocket.js
import { useEffect, useState, useCallback } from 'react';
import * as signalR from '@microsoft/signalr';

export const useNotificationWebSocket = (clientId, accessToken) => {
    const [connection, setConnection] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [notifications, setNotifications] = useState([]);

    const connectWebSocket = useCallback(async () => {
        try {
            const newConnection = new signalR.HubConnectionBuilder()
                .withUrl('/notificationHub', {
                    accessTokenFactory: () => accessToken
                })
                .withAutomaticReconnect()
                .build();

            // Configurar eventos
            newConnection.on('LoginNotification', (data) => {
                console.log('Login notification received:', data);
                setNotifications(prev => [...prev, data]);
                
                // Procesar notificación de login
                if (data.eventType === 'Login') {
                    localStorage.setItem('user', JSON.stringify(data.data));
                    window.location.href = '/dashboard';
                }
            });

            newConnection.onreconnected(() => {
                console.log('WebSocket reconnected');
                setIsConnected(true);
                // Re-unirse al grupo de la aplicación
                newConnection.invoke('JoinApplicationGroup', clientId);
            });

            newConnection.onclose(() => {
                console.log('WebSocket disconnected');
                setIsConnected(false);
            });

            // Conectar
            await newConnection.start();
            console.log('WebSocket connected');
            
            // Unirse al grupo de la aplicación
            await newConnection.invoke('JoinApplicationGroup', clientId);
            
            setConnection(newConnection);
            setIsConnected(true);

        } catch (error) {
            console.error('Error connecting to WebSocket:', error);
        }
    }, [clientId, accessToken]);

    const disconnectWebSocket = useCallback(async () => {
        if (connection) {
            await connection.stop();
            setConnection(null);
            setIsConnected(false);
        }
    }, [connection]);

    useEffect(() => {
        if (clientId) {
            connectWebSocket();
        }

        return () => {
            disconnectWebSocket();
        };
    }, [clientId, accessToken, connectWebSocket, disconnectWebSocket]);

    return {
        isConnected,
        notifications,
        connection,
        reconnect: connectWebSocket,
        disconnect: disconnectWebSocket
    };
};
```

## ⚛️ Componente React de Login

Este componente inicia el login de Office365 y utiliza el hook para recibir notificaciones.

```javascript
// components/Office365Login.jsx
import React, { useEffect } from 'react';
import { useNotificationWebSocket } from '../hooks/useNotificationWebSocket';

const Office365Login = () => {
    const clientId = 'mi-app-frontend'; // Reemplazar con tu clientId
    const { isConnected, notifications } = useNotificationWebSocket(clientId, null);

    const handleOffice365Login = async () => {
        try {
            // 1. Obtener URL de Office365
            const response = await fetch(`/api/auth/azure/url?clientId=${clientId}`);
            const { url } = await response.json();
            
            // 2. Redirigir a Office365
            window.location.href = url;
            
        } catch (error) {
            console.error('Error initiating Office365 login:', error);
        }
    };

    useEffect(() => {
        // Procesar notificaciones recibidas
        notifications.forEach(notification => {
            if (notification.eventType === 'Login') {
                console.log('User logged in:', notification.data);
                // Actualizar estado de la aplicación, guardar token, etc.
            }
        });
    }, [notifications]);

    return (
        <div>
            <div>
                WebSocket Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </div>
            
            <button onClick={handleOffice365Login}>
                Login with Office365
            </button>
            
            {notifications.length > 0 && (
                <div>
                    <h3>Recent Notifications:</h3>
                    {notifications.map((notif, index) => (
                        <div key={index}>
                            {notif.eventType}: {notif.data.email}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default Office365Login;
```

## 🔄 Flujo de Uso

1.  **Montar Componente**: Al montar el componente `Office365Login`, el hook `useNotificationWebSocket` se conecta automáticamente al backend.
2.  **Unirse a Grupo**: El hook invoca `JoinApplicationGroup` en el backend para empezar a recibir notificaciones de esa aplicación.
3.  **Iniciar Login**: El usuario hace clic en el botón y es redirigido a Office365.
4.  **Recibir Notificación**: Después del login exitoso, el backend envía una notificación `LoginNotification` al grupo de la aplicación.
5.  **Procesar Notificación**: El hook recibe la notificación, la agrega al estado `notifications` y el componente la procesa (ej: redirige al dashboard).

## 📊 Ventajas de esta Implementación

- **Reutilizable**: El hook se puede usar en cualquier parte de la aplicación.
- **Resiliente**: `withAutomaticReconnect` maneja desconexiones temporales.
- **Seguro**: `accessTokenFactory` permite pasar un token JWT para autenticar la conexión.
- **Eficiente**: Una sola conexión WebSocket para todas las notificaciones.
- **En tiempo real**: La UX es inmediata después del login.



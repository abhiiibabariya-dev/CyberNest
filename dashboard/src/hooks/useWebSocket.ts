import { useEffect, useRef, useState, useCallback } from 'react';
import { useCyberNestStore } from '@/store';

interface UseWebSocketOptions {
  onMessage?: (data: unknown) => void;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export function useWebSocket(url: string, options: UseWebSocketOptions = {}) {
  const { reconnectInterval = 5000, maxReconnectAttempts = 20 } = options;
  const [messages, setMessages] = useState<unknown[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<number>();
  const reconnectAttempts = useRef(0);
  const setWebSocketConnected = useCyberNestStore((s) => s.setWebSocketConnected);

  const connect = useCallback(() => {
    const token = localStorage.getItem('cybernest_token');
    if (!token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}${url}${token ? `?token=${token}` : ''}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setWebSocketConnected(true);
        reconnectAttempts.current = 0;
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current);
          reconnectTimer.current = undefined;
        }
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setMessages((prev) => [data, ...prev.slice(0, 99)]);
          options.onMessage?.(data);
        } catch {
          // Ignore non-JSON messages
        }
      };

      ws.onclose = (event) => {
        setIsConnected(false);
        setWebSocketConnected(false);
        wsRef.current = null;

        // Don't reconnect if closed cleanly or max attempts reached
        if (event.code === 1000 || reconnectAttempts.current >= maxReconnectAttempts) return;

        reconnectAttempts.current += 1;
        const delay = Math.min(reconnectInterval * Math.pow(1.5, reconnectAttempts.current - 1), 30000);
        reconnectTimer.current = window.setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      // WebSocket creation failed, schedule reconnect
      reconnectTimer.current = window.setTimeout(connect, reconnectInterval);
    }
  }, [url, reconnectInterval, maxReconnectAttempts, setWebSocketConnected, options]);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmounting');
      }
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
      }
    };
  }, [connect]);

  const sendMessage = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return {
    messages,
    isConnected,
    sendMessage,
    clearMessages: () => setMessages([]),
  };
}

import { useEffect, useRef, useState, useCallback } from 'react'

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<unknown[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number>()

  const connect = useCallback(() => {
    const token = localStorage.getItem('cybernest_token')
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${url}${token ? `?token=${token}` : ''}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setIsConnected(true)
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setMessages(prev => [data, ...prev.slice(0, 99)])
      } catch {}
    }

    ws.onclose = () => {
      setIsConnected(false)
      reconnectTimer.current = window.setTimeout(connect, 5000)
    }

    ws.onerror = () => ws.close()
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      wsRef.current?.close()
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
    }
  }, [connect])

  return { messages, isConnected, clearMessages: () => setMessages([]) }
}

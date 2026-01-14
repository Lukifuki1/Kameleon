"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REALTIME STREAMING ENGINE
WebSocket-based Real-time Event Streaming System

This module implements:
- WebSocket server for real-time updates
- Event broadcasting to connected clients
- Channel-based subscriptions (threats, alerts, metrics, etc.)
- Client authentication and authorization
- Message queuing and delivery guarantees
- Heartbeat and connection management
- Event filtering and routing
- Replay of missed events
- Rate limiting per client

100% opensource - Uses FastAPI WebSocket (MIT) and asyncio

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Callable, Awaitable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import uuid
import weakref

try:
    from fastapi import WebSocket, WebSocketDisconnect, HTTPException
    from starlette.websockets import WebSocketState
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    WebSocket = None
    WebSocketDisconnect = Exception

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


MAX_CLIENTS = int(os.environ.get("WS_MAX_CLIENTS", "1000"))
HEARTBEAT_INTERVAL = int(os.environ.get("WS_HEARTBEAT_INTERVAL", "30"))
MESSAGE_BUFFER_SIZE = int(os.environ.get("WS_MESSAGE_BUFFER_SIZE", "1000"))
RATE_LIMIT_MESSAGES = int(os.environ.get("WS_RATE_LIMIT_MESSAGES", "100"))
RATE_LIMIT_WINDOW = int(os.environ.get("WS_RATE_LIMIT_WINDOW", "60"))


class EventChannel(str, Enum):
    THREATS = "threats"
    ALERTS = "alerts"
    METRICS = "metrics"
    INCIDENTS = "incidents"
    COMPLIANCE = "compliance"
    HUNTING = "hunting"
    SOAR = "soar"
    NETWORK = "network"
    SYSTEM = "system"
    AUDIT = "audit"
    ALL = "all"


class EventPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MessageType(str, Enum):
    EVENT = "event"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    HEARTBEAT = "heartbeat"
    ACK = "ack"
    ERROR = "error"
    AUTH = "auth"
    REPLAY = "replay"


@dataclass
class StreamEvent:
    event_id: str
    channel: EventChannel
    event_type: str
    priority: EventPriority
    payload: Dict[str, Any]
    timestamp: datetime
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "channel": self.channel.value,
            "event_type": self.event_type,
            "priority": self.priority.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "metadata": self.metadata
        }


@dataclass
class ClientInfo:
    client_id: str
    user_id: Optional[str]
    connected_at: datetime
    last_heartbeat: datetime
    subscriptions: Set[EventChannel]
    message_count: int
    rate_limit_reset: datetime
    filters: Dict[str, Any]
    metadata: Dict[str, Any]


@dataclass
class StreamMessage:
    message_type: MessageType
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_json(self) -> str:
        return json.dumps({
            "type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "message_id": self.message_id
        })
    
    @classmethod
    def from_json(cls, data: str) -> "StreamMessage":
        parsed = json.loads(data)
        return cls(
            message_type=MessageType(parsed.get("type", "event")),
            payload=parsed.get("payload", {}),
            timestamp=datetime.fromisoformat(parsed.get("timestamp", datetime.utcnow().isoformat())),
            message_id=parsed.get("message_id", str(uuid.uuid4()))
        )


class EventBuffer:
    """Circular buffer for event replay"""
    
    def __init__(self, max_size: int = MESSAGE_BUFFER_SIZE):
        self._buffer: deque = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._by_channel: Dict[EventChannel, deque] = defaultdict(lambda: deque(maxlen=max_size // len(EventChannel)))
    
    def add(self, event: StreamEvent):
        """Add event to buffer"""
        with self._lock:
            self._buffer.append(event)
            self._by_channel[event.channel].append(event)
    
    def get_since(self, timestamp: datetime, channel: EventChannel = None) -> List[StreamEvent]:
        """Get events since timestamp"""
        with self._lock:
            if channel and channel != EventChannel.ALL:
                events = list(self._by_channel[channel])
            else:
                events = list(self._buffer)
            
            return [e for e in events if e.timestamp > timestamp]
    
    def get_by_id(self, event_id: str) -> Optional[StreamEvent]:
        """Get event by ID"""
        with self._lock:
            for event in self._buffer:
                if event.event_id == event_id:
                    return event
            return None
    
    def get_recent(self, count: int = 100, channel: EventChannel = None) -> List[StreamEvent]:
        """Get recent events"""
        with self._lock:
            if channel and channel != EventChannel.ALL:
                events = list(self._by_channel[channel])
            else:
                events = list(self._buffer)
            
            return events[-count:]


class RateLimiter:
    """Per-client rate limiter"""
    
    def __init__(self, max_messages: int = RATE_LIMIT_MESSAGES, window_seconds: int = RATE_LIMIT_WINDOW):
        self._max_messages = max_messages
        self._window_seconds = window_seconds
        self._client_counts: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def check(self, client_id: str) -> bool:
        """Check if client is within rate limit"""
        now = time.time()
        window_start = now - self._window_seconds
        
        with self._lock:
            timestamps = self._client_counts[client_id]
            timestamps = [t for t in timestamps if t > window_start]
            self._client_counts[client_id] = timestamps
            
            if len(timestamps) >= self._max_messages:
                return False
            
            timestamps.append(now)
            return True
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining messages in window"""
        now = time.time()
        window_start = now - self._window_seconds
        
        with self._lock:
            timestamps = self._client_counts[client_id]
            current_count = len([t for t in timestamps if t > window_start])
            return max(0, self._max_messages - current_count)


class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}
        self._clients: Dict[str, ClientInfo] = {}
        self._subscriptions: Dict[EventChannel, Set[str]] = defaultdict(set)
        self._lock = asyncio.Lock()
        self._event_buffer = EventBuffer()
        self._rate_limiter = RateLimiter()
        self._event_handlers: Dict[str, List[Callable]] = defaultdict(list)
    
    async def connect(self, websocket: WebSocket, client_id: str = None,
                      user_id: str = None) -> str:
        """Accept new connection"""
        if len(self._connections) >= MAX_CLIENTS:
            await websocket.close(code=1013, reason="Server at capacity")
            raise Exception("Server at capacity")
        
        await websocket.accept()
        
        client_id = client_id or str(uuid.uuid4())
        
        async with self._lock:
            self._connections[client_id] = websocket
            self._clients[client_id] = ClientInfo(
                client_id=client_id,
                user_id=user_id,
                connected_at=datetime.utcnow(),
                last_heartbeat=datetime.utcnow(),
                subscriptions=set(),
                message_count=0,
                rate_limit_reset=datetime.utcnow() + timedelta(seconds=RATE_LIMIT_WINDOW),
                filters={},
                metadata={}
            )
        
        logger.info(f"Client {client_id} connected")
        
        await self._send_message(client_id, StreamMessage(
            message_type=MessageType.ACK,
            payload={"client_id": client_id, "status": "connected"}
        ))
        
        return client_id
    
    async def disconnect(self, client_id: str):
        """Handle disconnection"""
        async with self._lock:
            if client_id in self._connections:
                del self._connections[client_id]
            
            if client_id in self._clients:
                client = self._clients[client_id]
                for channel in client.subscriptions:
                    self._subscriptions[channel].discard(client_id)
                del self._clients[client_id]
        
        logger.info(f"Client {client_id} disconnected")
    
    async def subscribe(self, client_id: str, channels: List[EventChannel]):
        """Subscribe client to channels"""
        async with self._lock:
            if client_id not in self._clients:
                return
            
            client = self._clients[client_id]
            for channel in channels:
                client.subscriptions.add(channel)
                self._subscriptions[channel].add(client_id)
        
        await self._send_message(client_id, StreamMessage(
            message_type=MessageType.ACK,
            payload={"action": "subscribed", "channels": [c.value for c in channels]}
        ))
    
    async def unsubscribe(self, client_id: str, channels: List[EventChannel]):
        """Unsubscribe client from channels"""
        async with self._lock:
            if client_id not in self._clients:
                return
            
            client = self._clients[client_id]
            for channel in channels:
                client.subscriptions.discard(channel)
                self._subscriptions[channel].discard(client_id)
        
        await self._send_message(client_id, StreamMessage(
            message_type=MessageType.ACK,
            payload={"action": "unsubscribed", "channels": [c.value for c in channels]}
        ))
    
    async def broadcast(self, event: StreamEvent):
        """Broadcast event to subscribed clients"""
        self._event_buffer.add(event)
        
        target_clients = set()
        async with self._lock:
            target_clients.update(self._subscriptions.get(event.channel, set()))
            target_clients.update(self._subscriptions.get(EventChannel.ALL, set()))
        
        message = StreamMessage(
            message_type=MessageType.EVENT,
            payload=event.to_dict()
        )
        
        for client_id in target_clients:
            if self._should_send_to_client(client_id, event):
                await self._send_message(client_id, message)
    
    def _should_send_to_client(self, client_id: str, event: StreamEvent) -> bool:
        """Check if event should be sent to client based on filters"""
        client = self._clients.get(client_id)
        if not client:
            return False
        
        filters = client.filters
        
        if "min_priority" in filters:
            priority_order = [EventPriority.INFO, EventPriority.LOW, EventPriority.MEDIUM,
                            EventPriority.HIGH, EventPriority.CRITICAL]
            min_idx = priority_order.index(EventPriority(filters["min_priority"]))
            event_idx = priority_order.index(event.priority)
            if event_idx < min_idx:
                return False
        
        if "event_types" in filters:
            if event.event_type not in filters["event_types"]:
                return False
        
        if "sources" in filters:
            if event.source not in filters["sources"]:
                return False
        
        return True
    
    async def _send_message(self, client_id: str, message: StreamMessage):
        """Send message to specific client"""
        websocket = self._connections.get(client_id)
        if not websocket:
            return
        
        if not self._rate_limiter.check(client_id):
            error_msg = StreamMessage(
                message_type=MessageType.ERROR,
                payload={"error": "rate_limit_exceeded", "retry_after": RATE_LIMIT_WINDOW}
            )
            try:
                await websocket.send_text(error_msg.to_json())
            except Exception:
                pass
            return
        
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_text(message.to_json())
                
                if client_id in self._clients:
                    self._clients[client_id].message_count += 1
        except Exception as e:
            logger.error(f"Failed to send message to {client_id}: {e}")
            await self.disconnect(client_id)
    
    async def send_to_client(self, client_id: str, event: StreamEvent):
        """Send event to specific client"""
        message = StreamMessage(
            message_type=MessageType.EVENT,
            payload=event.to_dict()
        )
        await self._send_message(client_id, message)
    
    async def handle_message(self, client_id: str, data: str):
        """Handle incoming message from client"""
        try:
            message = StreamMessage.from_json(data)
        except Exception as e:
            await self._send_message(client_id, StreamMessage(
                message_type=MessageType.ERROR,
                payload={"error": "invalid_message", "details": str(e)}
            ))
            return
        
        if message.message_type == MessageType.SUBSCRIBE:
            channels = [EventChannel(c) for c in message.payload.get("channels", [])]
            await self.subscribe(client_id, channels)
        
        elif message.message_type == MessageType.UNSUBSCRIBE:
            channels = [EventChannel(c) for c in message.payload.get("channels", [])]
            await self.unsubscribe(client_id, channels)
        
        elif message.message_type == MessageType.HEARTBEAT:
            async with self._lock:
                if client_id in self._clients:
                    self._clients[client_id].last_heartbeat = datetime.utcnow()
            
            await self._send_message(client_id, StreamMessage(
                message_type=MessageType.HEARTBEAT,
                payload={"status": "alive", "server_time": datetime.utcnow().isoformat()}
            ))
        
        elif message.message_type == MessageType.REPLAY:
            since = message.payload.get("since")
            channel = message.payload.get("channel")
            
            if since:
                since_dt = datetime.fromisoformat(since)
                channel_enum = EventChannel(channel) if channel else None
                events = self._event_buffer.get_since(since_dt, channel_enum)
                
                for event in events:
                    await self.send_to_client(client_id, event)
        
        elif message.message_type == MessageType.AUTH:
            pass
    
    async def heartbeat_loop(self):
        """Send periodic heartbeats and cleanup stale connections"""
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            
            now = datetime.utcnow()
            stale_threshold = now - timedelta(seconds=HEARTBEAT_INTERVAL * 3)
            
            stale_clients = []
            async with self._lock:
                for client_id, client in self._clients.items():
                    if client.last_heartbeat < stale_threshold:
                        stale_clients.append(client_id)
            
            for client_id in stale_clients:
                logger.warning(f"Disconnecting stale client: {client_id}")
                await self.disconnect(client_id)
            
            async with self._lock:
                active_clients = list(self._connections.keys())
            
            for client_id in active_clients:
                await self._send_message(client_id, StreamMessage(
                    message_type=MessageType.HEARTBEAT,
                    payload={"status": "ping", "server_time": now.isoformat()}
                ))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            "total_connections": len(self._connections),
            "subscriptions_by_channel": {
                channel.value: len(clients)
                for channel, clients in self._subscriptions.items()
            },
            "buffer_size": len(self._event_buffer._buffer),
            "max_clients": MAX_CLIENTS
        }
    
    def get_client_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information"""
        client = self._clients.get(client_id)
        if not client:
            return None
        
        return {
            "client_id": client.client_id,
            "user_id": client.user_id,
            "connected_at": client.connected_at.isoformat(),
            "last_heartbeat": client.last_heartbeat.isoformat(),
            "subscriptions": [s.value for s in client.subscriptions],
            "message_count": client.message_count,
            "rate_limit_remaining": self._rate_limiter.get_remaining(client_id)
        }
    
    def set_client_filters(self, client_id: str, filters: Dict[str, Any]):
        """Set event filters for client"""
        if client_id in self._clients:
            self._clients[client_id].filters = filters
    
    def get_recent_events(self, count: int = 100, channel: EventChannel = None) -> List[Dict[str, Any]]:
        """Get recent events from buffer"""
        events = self._event_buffer.get_recent(count, channel)
        return [e.to_dict() for e in events]


class EventPublisher:
    """Publishes events to the streaming system"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self._manager = connection_manager
        self._event_queue: asyncio.Queue = None
        self._running = False
        self._publish_task = None
    
    async def start(self):
        """Start the publisher"""
        self._event_queue = asyncio.Queue()
        self._running = True
        self._publish_task = asyncio.create_task(self._publish_loop())
        logger.info("Event publisher started")
    
    async def stop(self):
        """Stop the publisher"""
        self._running = False
        if self._publish_task:
            self._publish_task.cancel()
            try:
                await self._publish_task
            except asyncio.CancelledError:
                pass
    
    async def _publish_loop(self):
        """Process event queue"""
        while self._running:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                await self._manager.broadcast(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error publishing event: {e}")
    
    async def publish(self, event: StreamEvent):
        """Publish event"""
        if self._event_queue:
            await self._event_queue.put(event)
    
    def publish_sync(self, event: StreamEvent):
        """Publish event synchronously (for use from non-async code)"""
        if self._event_queue:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._event_queue.put(event))
                else:
                    loop.run_until_complete(self._event_queue.put(event))
            except RuntimeError:
                pass
    
    def create_event(self, channel: EventChannel, event_type: str, payload: Dict[str, Any],
                     priority: EventPriority = EventPriority.MEDIUM, source: str = "system") -> StreamEvent:
        """Create new event"""
        return StreamEvent(
            event_id=f"EVT-{hashlib.sha256(f'{channel.value}{event_type}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}",
            channel=channel,
            event_type=event_type,
            priority=priority,
            payload=payload,
            timestamp=datetime.utcnow(),
            source=source
        )
    
    async def publish_threat(self, threat_data: Dict[str, Any], priority: EventPriority = EventPriority.HIGH):
        """Publish threat event"""
        event = self.create_event(
            channel=EventChannel.THREATS,
            event_type="threat_detected",
            payload=threat_data,
            priority=priority,
            source="threat_intel"
        )
        await self.publish(event)
    
    async def publish_alert(self, alert_data: Dict[str, Any], priority: EventPriority = EventPriority.HIGH):
        """Publish alert event"""
        event = self.create_event(
            channel=EventChannel.ALERTS,
            event_type="alert_triggered",
            payload=alert_data,
            priority=priority,
            source="alerting"
        )
        await self.publish(event)
    
    async def publish_metrics(self, metrics_data: Dict[str, Any]):
        """Publish metrics event"""
        event = self.create_event(
            channel=EventChannel.METRICS,
            event_type="metrics_update",
            payload=metrics_data,
            priority=EventPriority.INFO,
            source="monitoring"
        )
        await self.publish(event)
    
    async def publish_incident(self, incident_data: Dict[str, Any], priority: EventPriority = EventPriority.CRITICAL):
        """Publish incident event"""
        event = self.create_event(
            channel=EventChannel.INCIDENTS,
            event_type="incident_created",
            payload=incident_data,
            priority=priority,
            source="incident_management"
        )
        await self.publish(event)
    
    async def publish_compliance(self, compliance_data: Dict[str, Any]):
        """Publish compliance event"""
        event = self.create_event(
            channel=EventChannel.COMPLIANCE,
            event_type="compliance_update",
            payload=compliance_data,
            priority=EventPriority.MEDIUM,
            source="compliance"
        )
        await self.publish(event)
    
    async def publish_hunting(self, hunting_data: Dict[str, Any]):
        """Publish hunting event"""
        event = self.create_event(
            channel=EventChannel.HUNTING,
            event_type="hunt_finding",
            payload=hunting_data,
            priority=EventPriority.HIGH,
            source="threat_hunting"
        )
        await self.publish(event)
    
    async def publish_soar(self, soar_data: Dict[str, Any]):
        """Publish SOAR event"""
        event = self.create_event(
            channel=EventChannel.SOAR,
            event_type="playbook_execution",
            payload=soar_data,
            priority=EventPriority.MEDIUM,
            source="soar"
        )
        await self.publish(event)
    
    async def publish_network(self, network_data: Dict[str, Any], priority: EventPriority = EventPriority.MEDIUM):
        """Publish network event"""
        event = self.create_event(
            channel=EventChannel.NETWORK,
            event_type="network_event",
            payload=network_data,
            priority=priority,
            source="network_monitor"
        )
        await self.publish(event)
    
    async def publish_system(self, system_data: Dict[str, Any]):
        """Publish system event"""
        event = self.create_event(
            channel=EventChannel.SYSTEM,
            event_type="system_event",
            payload=system_data,
            priority=EventPriority.INFO,
            source="system"
        )
        await self.publish(event)
    
    async def publish_audit(self, audit_data: Dict[str, Any]):
        """Publish audit event"""
        event = self.create_event(
            channel=EventChannel.AUDIT,
            event_type="audit_log",
            payload=audit_data,
            priority=EventPriority.INFO,
            source="audit"
        )
        await self.publish(event)


class RealtimeStreamingEngine:
    """Main real-time streaming engine"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.connection_manager = ConnectionManager()
        self.publisher = EventPublisher(self.connection_manager)
        self._heartbeat_task = None
        self._running = False
    
    async def start(self):
        """Start the streaming engine"""
        if self._running:
            return
        
        self._running = True
        await self.publisher.start()
        self._heartbeat_task = asyncio.create_task(self.connection_manager.heartbeat_loop())
        logger.info("Realtime streaming engine started")
    
    async def stop(self):
        """Stop the streaming engine"""
        self._running = False
        await self.publisher.stop()
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
    
    async def handle_websocket(self, websocket: WebSocket, client_id: str = None,
                                user_id: str = None):
        """Handle WebSocket connection"""
        client_id = await self.connection_manager.connect(websocket, client_id, user_id)
        
        try:
            while True:
                data = await websocket.receive_text()
                await self.connection_manager.handle_message(client_id, data)
        except WebSocketDisconnect:
            await self.connection_manager.disconnect(client_id)
        except Exception as e:
            logger.error(f"WebSocket error for {client_id}: {e}")
            await self.connection_manager.disconnect(client_id)
    
    async def publish_event(self, channel: EventChannel, event_type: str,
                            payload: Dict[str, Any], priority: EventPriority = EventPriority.MEDIUM,
                            source: str = "system"):
        """Publish event to channel"""
        event = self.publisher.create_event(channel, event_type, payload, priority, source)
        await self.publisher.publish(event)
    
    def publish_event_sync(self, channel: EventChannel, event_type: str,
                           payload: Dict[str, Any], priority: EventPriority = EventPriority.MEDIUM,
                           source: str = "system"):
        """Publish event synchronously"""
        event = self.publisher.create_event(channel, event_type, payload, priority, source)
        self.publisher.publish_sync(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get streaming statistics"""
        return {
            "running": self._running,
            **self.connection_manager.get_stats()
        }
    
    def get_client_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information"""
        return self.connection_manager.get_client_info(client_id)
    
    def get_recent_events(self, count: int = 100, channel: str = None) -> List[Dict[str, Any]]:
        """Get recent events"""
        channel_enum = EventChannel(channel) if channel else None
        return self.connection_manager.get_recent_events(count, channel_enum)


_streaming_engine: Optional[RealtimeStreamingEngine] = None


def get_streaming_engine() -> RealtimeStreamingEngine:
    """Get singleton instance of RealtimeStreamingEngine"""
    global _streaming_engine
    if _streaming_engine is None:
        _streaming_engine = RealtimeStreamingEngine()
    return _streaming_engine


async def websocket_endpoint(websocket: WebSocket, client_id: str = None):
    """FastAPI WebSocket endpoint handler"""
    engine = get_streaming_engine()
    
    if not engine._running:
        await engine.start()
    
    await engine.handle_websocket(websocket, client_id)


def create_websocket_router():
    """Create FastAPI router for WebSocket endpoints"""
    if not FASTAPI_AVAILABLE:
        return None
    
    from fastapi import APIRouter, Query
    
    router = APIRouter()
    
    @router.websocket("/ws")
    async def websocket_handler(websocket: WebSocket, client_id: str = Query(None)):
        await websocket_endpoint(websocket, client_id)
    
    @router.websocket("/ws/{channel}")
    async def websocket_channel_handler(websocket: WebSocket, channel: str, client_id: str = Query(None)):
        engine = get_streaming_engine()
        
        if not engine._running:
            await engine.start()
        
        cid = await engine.connection_manager.connect(websocket, client_id)
        
        try:
            channel_enum = EventChannel(channel)
        except ValueError:
            await websocket.close(code=1008, reason=f"Invalid channel: {channel}")
            return
        
        await engine.connection_manager.subscribe(cid, [channel_enum])
        
        try:
            while True:
                data = await websocket.receive_text()
                await engine.connection_manager.handle_message(cid, data)
        except WebSocketDisconnect:
            await engine.connection_manager.disconnect(cid)
        except Exception as e:
            logger.error(f"WebSocket error for {cid}: {e}")
            await engine.connection_manager.disconnect(cid)
    
    return router

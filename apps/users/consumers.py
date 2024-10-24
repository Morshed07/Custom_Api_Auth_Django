import json
from channels.generic.websocket import AsyncWebsocketConsumer

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Join a common notification group
        await self.channel_layer.group_add("notifications", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the group on disconnect
        await self.channel_layer.group_discard("notifications", self.channel_name)

    async def receive(self, text_data):
        # Handle messages received from WebSocket clients
        pass

    async def send_notification(self, event):
        # Send notification message to WebSocket client
        await self.send(text_data=json.dumps({
            'message': event['message']
        }))

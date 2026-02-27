package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
)

func (t *tunnel) handleWSOpen(ctx context.Context, msg tunnelMessage) {
	connectionID := msg.ConnectionID
	path := msg.Path
	query := msg.Query

	target := fmt.Sprintf("ws://%s:%d%s", t.localHost, t.localPort, path)
	if query != "" {
		target = target + "?" + query
	}

	logInfo("ws_open conn=%s path=%s", connectionID, path)

	localConn, _, err := websocket.DefaultDialer.DialContext(ctx, target, http.Header{})
	if err != nil {
		logError("ws_open failed conn=%s error=%v", connectionID, err)
		_ = t.wsSend(tunnelMessage{
			Type:         "ws_close",
			ConnectionID: connectionID,
			Code:         1011,
			Reason:       fmt.Sprintf("unable to open local websocket: %v", err),
		})
		return
	}

	t.bridgesMu.Lock()
	t.bridges[connectionID] = localConn
	t.bridgesMu.Unlock()

	go t.pumpLocalToGateway(ctx, connectionID, localConn)
}

func (t *tunnel) pumpLocalToGateway(ctx context.Context, connectionID string, localConn *websocket.Conn) {
	defer func() {
		t.bridgesMu.Lock()
		delete(t.bridges, connectionID)
		t.bridgesMu.Unlock()
		_ = localConn.Close()
	}()

	go func() {
		<-ctx.Done()
		_ = localConn.Close()
	}()

	for {
		messageType, payload, err := localConn.ReadMessage()
		if err != nil {
			_ = t.wsSend(tunnelMessage{
				Type:         "ws_close",
				ConnectionID: connectionID,
				Code:         1000,
				Reason:       "local websocket closed",
			})
			return
		}

		opcode := "text"
		if messageType == websocket.BinaryMessage {
			opcode = "binary"
		}
		logDebug("ws_data send conn=%s opcode=%s len=%d", connectionID, opcode, len(payload))
		_ = t.wsSend(tunnelMessage{
			Type:         "ws_data",
			ConnectionID: connectionID,
			Opcode:       opcode,
			DataB64:      base64.StdEncoding.EncodeToString(payload),
		})
	}
}

func (t *tunnel) handleWSData(msg tunnelMessage) {
	connectionID := msg.ConnectionID
	logDebug("ws_data recv conn=%s opcode=%s len=%d", connectionID, msg.Opcode, len(msg.DataB64))

	t.bridgesMu.Lock()
	localConn := t.bridges[connectionID]
	t.bridgesMu.Unlock()
	if localConn == nil {
		logDebug("ws_data no bridge for conn=%s", connectionID)
		return
	}

	payload, err := base64.StdEncoding.DecodeString(msg.DataB64)
	if err != nil {
		logError("ws_data decode error conn=%s: %v", connectionID, err)
		return
	}

	messageType := websocket.TextMessage
	if msg.Opcode == "binary" {
		messageType = websocket.BinaryMessage
	}
	if err := localConn.WriteMessage(messageType, payload); err != nil {
		logError("ws_data write error conn=%s: %v", connectionID, err)
	}
}

func (t *tunnel) handleWSClose(msg tunnelMessage) {
	connectionID := msg.ConnectionID
	logInfo("ws_close conn=%s", connectionID)

	t.bridgesMu.Lock()
	localConn := t.bridges[connectionID]
	delete(t.bridges, connectionID)
	t.bridgesMu.Unlock()

	if localConn != nil {
		_ = localConn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(msg.Code, msg.Reason),
		)
		_ = localConn.Close()
	}
}

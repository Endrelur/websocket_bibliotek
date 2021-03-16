const EventEmitter = require('events').EventEmitter;

/**
 * A class handling a websocket connection i compliance with rfc6455.
 * Created by Endré Hadzalic.
 * //TODO: fix problem with error on client disconnect.
 */
class WebSocket extends EventEmitter {

    #wsServer
    #debug = false;

    /**
     *
     * @param {boolean} debug if true, sets the server to debug mode, false if not.
     */
    constructor(debug) {
        super();
        this.#debug = debug;
    }

    /**
     * Makes the server listen for WebSocket connections on the given port param.
     *
     * @param {integer} port the port to listen for connections on.
     */
    listen(port) {
        let net = require('net');
        this.#wsServer = net.createServer((connection) => {
            if (this.#debug)
                console.log("WebSocket connected to client: " + connection.localAddress);
            connection.on('data', data => {
                if (this.#isHandshake(data)) {
                    //The received date is a websocket handshake request.
                    if (this.#debug)
                        console.log("WebSocket received handshake request: " + data.toString());
                    //Handle the request and reply in the right manner.
                    this.#handleHandshake(data, connection);
                } else { //The received data was not a handshake.
                    let message = this.#parseMessage(data)
                    if (this.#debug) {
                        console.log("WebSocket received data:\n" +
                            "parsed: " + message + "\n"
                            + "not parsed: " + data.toString('hex'));
                    }
                    this.emit('message', connection, message); //emit the connection to a listener for custom handling
                }
            });
            connection.on('end', () => {
                if (this.#debug)
                    console.log("Client disconnected");
            });
        });
        this.#wsServer.on('error', (error) => {
            console.error('Error: ', error);
        });
        this.#wsServer.listen(port, () => {
            if (this.#debug) {
                console.log("WebSocket listens on port: " + port);
            }
        });
    }

    /**
     * Takes in a string message and formats it into a format understandable for a client over a WebSocket connection.
     *
     * @param {string} message The string to format.
     * @returns {Buffer} the given message formatted in Buffer format.
     */
    webSocketMsgFormat(message) {
        // Convert the data to JSON and copy it into a buffer
        const json = JSON.stringify(message)
        const jsonByteLength = Buffer.byteLength(json);
        // Note: we're not supporting > 65535 byte payloads at this stage
        const lengthByteCount = jsonByteLength < 126 ? 0 : 2;
        const payloadLength = lengthByteCount === 0 ? jsonByteLength : 126;
        const buffer = Buffer.alloc(2 + lengthByteCount + jsonByteLength);
        // Write out the first byte, using opcode `1` to indicate that the message
        // payload contains text data
        buffer.writeUInt8(0b10000001, 0);
        buffer.writeUInt8(payloadLength, 1);
        // Write the length of the JSON payload to the second byte
        let payloadOffset = 2;
        if (lengthByteCount > 0) {
            buffer.writeUInt16BE(jsonByteLength, 2);
            payloadOffset += lengthByteCount;
        }
        buffer.write(json, payloadOffset);
        return buffer;
    }

    /**
     * Checks given data and if it is o WebSocket handshake.
     *
     * @param data the data to check.
     * @returns {boolean} true if it is a handshake, false if not.
     */
    #isHandshake(data) {

        function isHttp(data) {
            return data.toString().split('\n')[0].includes('HTTP/1.1');
        }

        function isSocketUpgradeRequest(data) {
            let isUpgrade = false;
            data.toString().split('\n').forEach(headerLine => {
                if (headerLine.includes('Upgrade: websocket')) {
                    isUpgrade = true;
                }
            });
            return isUpgrade;
        }

        return (isHttp(data) && isSocketUpgradeRequest(data));
    }

    /**
     * Decrypts a websocket-encrypted message.
     *
     * @param buffer the net.Buffer to decrypt.
     * @returns {string} a string representing the decrypted string.
     */
    #parseMessage(buffer) {
        let bytes = Buffer.from(buffer);
        let length = bytes[1] & 127;
        let maskStart = 2;
        let dataStart = maskStart + 4;
        let returnString = '';
        for (let i = dataStart; i < dataStart + length; i++) {
            let byte = bytes[i] ^ bytes[maskStart + ((i - dataStart) % 4)];
            returnString += String.fromCharCode(byte);
        }
        return returnString;
    }

    /**
     * Handles a WebSocket handshake in compliance to rfc6455;
     *
     * @param data the received data containing upgrade statement.
     * @param socket the connected socket.
     */
    #handleHandshake(data, socket) {
        function generateServerKey(key) {
            const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            return require('crypto')
                .createHash('sha1')//uses SHA-1 hash.
                .update(key + guid, 'binary')//concatenate the client key with the GUID.
                .digest('base64'); //encode in base64.
        }

        function getKeyFromHeader(data) {
            let key = null;
            data.toString().split('\n').forEach(headerLine => {
                //searches for the headerline that is related to the websocket key.
                if (headerLine.startsWith('Sec-WebSocket-Key:', 0)) {
                    //found the line, now saves the key to a local let.
                    key = headerLine.substr(19).slice(0, -1);
                }
            });
            return key;
        }

        const secKey = getKeyFromHeader(data);
        if (secKey !== null) {
            const msg =
                'HTTP/1.1 101 Switching Protocols\r\n' +
                'Upgrade: websocket\r\n' +
                'Connection: Upgrade\r\n' +
                'Sec-WebSocket-Accept: ' + generateServerKey(secKey) + '\r\n\r\n';
            socket.write(msg);
            if (this.#debug)
                console.log("WebSocket replied to Upgrade: Socket request with: \n" + msg);

        } else {
            socket.end('HTTP/1.1 400 Bad Request');
        }

    }
}

module.exports.WebSocket = WebSocket;
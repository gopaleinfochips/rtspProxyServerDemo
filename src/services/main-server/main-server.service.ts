import { Injectable } from '@nestjs/common';
import * as net from 'net';
import { v4 as uuidv4 } from 'uuid';
import * as dgram from "dgram";
import * as fs from 'fs'
import { parse as urlParse } from "url";
import { EventEmitter } from "events";
import * as crypto from "crypto";
import { RtspclientService } from '../rtspclient/rtspclient.service';
import RTSPClient from "../rtspclient/RTSPClient";
import H264Transport from "../../lib/transports/H264Transport";
import H265Transport from "../../lib/transports/H265Transport";
import AACTransport from "../../lib/transports/AACTransport";
import {
    parseRTPPacket,
    parseRTCPPacket,
    getMD5Hash,
    Transport,
    parseTransport,
    generateSSRC,
  } from "../../lib/util";
import { NewrtspclientService } from '../newrtspclient/newrtspclient.service';
  
enum ReadStates {
    SEARCHING,
    READING_RTSP_HEADER,
    READING_RTSP_PAYLOAD,
    READING_RAW_PACKET_SIZE,
    READING_RAW_PACKET,
  }
interface Details {
    codec: string
    mediaSource: any
    rtpChannel: number,
    rtcpChannel: number
  }
  
type Headers = {
    [key: string]: string | number | undefined;
    Session?: string;
    Location?: string;
    CSeq?: number;
    "WWW-Authenticate"?: string;
    Transport?: string;
    Unsupported?: string;
  };
  
@Injectable()
export class MainServerService {

    _nextFreeInterleavedChannel = 0;
    _nextFreeUDPPort = 5000;
  
    readState: ReadStates = ReadStates.SEARCHING;
  
    // Used as a cache for the data stream.
    // What's in here is based on current #readState.
    messageBytes: number[] = [];
  
    // Used for parsing RTSP responses,
  
    // Content-Length header in the RTSP message.
    rtspContentLength = 0;
    rtspStatusLine = "";
    rtspHeaders: Headers = {};
  
    // Used for parsing RTP/RTCP responses.
  
    rtspPacketLength = 0;
    rtspPacket: Buffer = new Buffer("");
    rtspPacketPointer = 0;
  
    // Used in #_emptyReceiverReport.
    clientSSRC = generateSSRC();

    public server: any;
    public clients: any = {};

    public rtpServer: any
    public rtcpServer: any
    rtpSequenceNumber = 0;
    rtpTimestamp = 0;
    MAX_RTP_PAYLOAD_SIZE = 1400; // Choose a size within the MTU limit (typically 1500 bytes for Ethernet)

    rtspUrl = 'rtsp://admin:einfochips@123@172.25.210.249:554/0/profile2/media.smp';
    rtspClient: any;
    h264Details :Details;

    isTCPClientRequest : boolean = false;
    version : string = 'RTSP/1.0'
    activeClientSocket : net.Socket;
    session :string;
    keepSessionIntevalId :any;
    constructor(
        private newRtspClientService : NewrtspclientService
    ) {
        this.rtpServer = dgram.createSocket('udp4');
        // this.rtcpServer =  dgram.createSocket('udp4');
        this.rtpServer.bind(() => {
            console.log(`RTP server listening on port ${this.rtpServer.address().port}`);
        });
        this.server = net.createServer(async (socket) => {
            const clientId = uuidv4();
            this.activeClientSocket = socket;
            this.clients[clientId] = { socket, state: 'INIT', session: null, transport: null, rtpPort: null, rtcpPort: null };
            console.log(`Client connected: ${clientId}`);
            this.observeRTSPConnection();

            socket.on('data', async (data) => {
                console.log(`Received data from ${clientId}: ${data.toString()}`);
                if (data[0] === 0x24) { // '$' symbol in ASCII
                    // This is an interleaved RTP/RTCP packet
                //     const channel = data[1];
                //     const packetLength = data.readUInt16BE(2);
                //     const rtpRtcpPacket = data.slice(4, 4 + packetLength);
                
                //     console.log(`Interleaved RTP/RTCP packet received on channel ${channel} with length ${packetLength}`);
                
                //     if (channel === 0 || channel === 2 || channel === 4) {
                //       this.handleRtpPacket(rtpRtcpPacket);
                //     } else if (channel === 1 || channel === 3 || channel === 5) {
                //       this.handleRtcpPacket(rtpRtcpPacket);
                //     }
                //    let rawRes = this.newRtspClientService.sendRawPacket(data);
                //    console.log("rawRes : ", rawRes);
                //     // this.rtspClient.socket.write(data);
                

                  } else {
                      this.handleRtspRequest(clientId, data.toString());
                  }
            });

            socket.on('end', () => {
                console.log(`Client disconnected: ${clientId}`);
                delete this.clients[clientId];
            });

            socket.on('error', (err) => {
                console.log(`Error with client ${clientId}: ${err.message}`);
                delete this.clients[clientId];
            });
        });

        this.server.listen(8554, () => {
            console.log('RTSP server listening on port 8554');
        });
       

    }

    async handleRtspRequest(clientId, request) {
        const client = this.clients[clientId];
        const socket = client.socket;
        const lines = request.split('\r\n');
        const [method, uri, version] = lines[0].split(' ');
        console.log("uri : ", uri);
        const headers :any = this.parseHeaders(lines.slice(1));
        console.log("headers : ", headers)

        console.log("-----request main:----- ", request)

        if (method === 'OPTIONS') {
            const response = [
                `${version} 200 OK`,
                `CSeq: ${headers['CSeq']}`,
                'Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN',
                '',
                ''
            ].join('\r\n');
            this.rtspClient =  await this.newRtspClientService.connect(this.rtspUrl);
            let optionResponse = await this.newRtspClientService.sendOption();
            console.log("optionResponse : ",  optionResponse);
            console.log(`Sending OPTIONS response to ${clientId} ===`, response);
            socket.write(response);
        } else if (method === 'DESCRIBE') {
           
            let describeRes :any = await this.newRtspClientService.sendDescribe();
            console.log("describeRes : ",  describeRes);
            let sepDescribeRes =  this.parseRTSPResponse(describeRes);

            console.log("sepDescribeRes: ", sepDescribeRes)
           
            let response = [
                `${version} 200 OK`,
                `CSeq: ${headers['CSeq']}`,
                'Content-Base: rtsp://localhost:8554/',
                `Cache-Control: ${sepDescribeRes.headers['Cache-Control']}`,
                `Content-Base:  ${sepDescribeRes.headers['Content-Base']}`,
                `Content-Type:  ${sepDescribeRes.headers['Content-Type']}`,
                `Content-Length: ${sepDescribeRes.headers['Content-Length']}`,
                `x-Accept-Retransmit: ${sepDescribeRes.headers['x-Accept-Retransmit']}`,
                `x-Accept-Dynamic-Rate: ${sepDescribeRes.headers['x-Accept-Dynamic-Rate']}`,
                '',
                ''
            ].join('\r\n');
            response = response + sepDescribeRes.mediaHeaders.join('\n');
            console.log("response : ", response);
            console.log(`Sending DESCRIBE response to ${clientId}`);
            socket.write(response);
        } else if (method === 'SETUP') {
            const transport = headers['Transport'];
            // let setupRequest = this.parseRTSPSetupRequest(request);
            // console.log("setupRequest : ", setupRequest);
            if (transport.includes('RTP/AVP/TCP')) {
                this.isTCPClientRequest = true;

                let setupRes :any =  await this.newRtspClientService.sendSetup(uri, transport, headers?.Session)
                let setupResParsed =  this.parseRTSPResponse(setupRes);
    
                console.log("setupRes ---------: ", setupResParsed)

                let response = [
                    `${version} 200 OK`,
                    `CSeq: ${headers['CSeq']}`,
                    'Content-Base: rtsp://localhost:8554/',
                    `Cache-Control: ${setupResParsed.headers['Cache-Control']}`,
                    `Transport: ${setupResParsed.headers['Transport']}`,
                    `Session: ${setupResParsed.headers['Session']}`,
                    '',
                    ''
                ].join('\r\n');
                console.log("response : ", response);
                console.log(`Sending SETUP response for TCP to ${clientId}`);
                socket.write(response);
            } else if (transport.includes('RTP/AVP;unicast')) {
                const clientPorts = transport.match(/client_port=(\d+)-(\d+)/);
                const rtpPort = parseInt(clientPorts[1], 10);
                const rtcpPort = parseInt(clientPorts[2], 10);
        
                const session = uuidv4();
                client.session = session;
                client.transport = transport;
                client.rtpPort = rtpPort;
                client.rtcpPort = rtcpPort;
    
                const response = [
                    `${version} 200 OK`,
                    `CSeq: ${headers['CSeq']}`,
                    `Transport: RTP/AVP;unicast;client_port=${rtpPort}-${rtcpPort};server_port=${this.rtpServer.address().port}-${this.rtpServer.address().port +1}`,
                    `Session: ${session}`,
                    '',
                    ''
                ].join('\r\n');
                console.log(`Sending SETUP response for UDP to ${clientId}`);
                socket.write(response);
            }
            client.state = 'READY';
        } else if (method === 'PLAY') {
            if (client.state !== 'READY') {
                const response = `${version} 455 Method Not Valid in This State\r\nCSeq: ${headers['CSeq']}\r\n\r\n`;
                console.log(`Sending error response to ${clientId}: 455 Method Not Valid in This State`);
                socket.write(response);
                return;
            }
            this.session = headers?.Session;
            let playurl = uri.replace('rtsp://localhost:8554/', this.newRtspClientService.path);
            console.log("playurl : ", playurl)
            let playRes :any =  await this.newRtspClientService.sendPlay(playurl, headers?.Session, headers?.Range )
            console.log("playRes : ", playRes);
            let playResParsed =  this.parseRTSPResponse(playRes);

            console.log("playResParsed: ", playResParsed)

            let response = [
                `${version} 200 OK`,
                `CSeq: ${headers['CSeq']}`,
                'Content-Base: rtsp://localhost:8554',
                `Cache-Control: ${playResParsed.headers['Cache-Control']}`,
                `Session: ${playResParsed.headers['Session']}`,
                `RTP-Info: ${playResParsed.headers['RTP-Info']}`,
                '',
                ''
            ].join('\r\n');
            console.log("response : ", response);
            
            console.log(`Sending PLAY response to ${clientId}`);
            socket.write(response);
            client.state = 'PLAYING';
            this.startDataOn(clientId)
        } else if (method === 'TEARDOWN') {
            const response = [
                `${version} 200 OK`,
                `CSeq: ${headers['CSeq']}`,
                `Session: ${client.session}`,
                '',
                ''
            ].join('\r\n');
            console.log(`Sending TEARDOWN response to ${clientId}`);
            await this.newRtspClientService.sendTeardown();
            socket.write(response);
            client.socket.end();
        } else {
            // const response = `${version} 501 Not Implemented\r\nCSeq: ${headers['CSeq']}\r\n\r\n`;
            // console.log(`Sending error response to ${clientId}: 501 Not Implemented`);
            // socket.write(response);
        }
    }

    startDataOn(clientId) {
        const client = this.clients[clientId];
        // const stream = fs.createReadStream(filePath, { highWaterMark: MAX_RTP_PAYLOAD_SIZE });
    
        let frameEnd = false; // Indicates the end of a frame (needs logic to determine actual end)
        this.rtspClient.on('data', (chunk) => {
            console.log('received data from camera');
            // if (client.tcpChannels) {
                // Interleave RTP packet with the RTP channel ID
            //    console.log("chunk : ", chunk);
                client.socket.write(chunk);
            // } else if (client.rtpPort) {
            //     rtpServer.send(rtpPacket, 0, rtpPacket.length, client.rtpPort, 'localhost', (err) => {
            //         if (err) console.error('Error sending RTP packet:', err);
            //     });
            // }
        });
        this.keepSessionAlive();
        setTimeout(()=>{
            this.pause();
        }, 3000)
    
    }

  async pause(){
    console.log(".................pause......................................")
       let pauseRes =  await this.newRtspClientService.sendPause(this.newRtspClientService.path, this.session); 
        console.log('pauseRes : ', pauseRes);
        setTimeout(async () => {
            console.log(".......................play...........................")
            let playRes :any =  await this.newRtspClientService.sendPlay(this.newRtspClientService.path,this.session, '0.00 -' )
            console.log("playRes : ", playRes);
          }, 5000);
    }

    keepSessionAlive(){
      this.keepSessionIntevalId =  setInterval(async ()=>{ 
            let optionResponse = await this.newRtspClientService.sendOption();
            console.log("optionResponse : ",  optionResponse);
        }, 50000 );
    }
    parseHeaders(headerLines) {
        const headers = {};
        headerLines.forEach(line => {
            if (line) {
                const [key, value] = line.split(': ');
                headers[key] = value;
            }
        });
        return headers;
    }

    observeRTSPConnection(){
       
        this.newRtspClientService.connectionStatus$.subscribe(data =>{
            console.log("observer data : ", data);
            if(data.type == 'error'){
                const response = [
                    `${this.version} 500 Internal Server Error`,
                    '',
                    '',
                    ''
                ].join('\r\n');
                try{
                    this.activeClientSocket.write(response);
                }catch(err){
                    console.log("end")
                }
            
                 this.clearInterval();
            
            }
            if(data.type == 'close'){
                this.clearInterval();
                const response = [
                    `${this.version} 500 Internal Server Error`,
                    '',
                    '',
                    ''
                ].join('\r\n');
                this.activeClientSocket.write(response);
            }
        })
    }

    clearInterval(){
        if(this.keepSessionIntevalId){
            clearInterval(this.keepSessionIntevalId);
            this.keepSessionIntevalId = '';
        }
    }
     handleRtpPacket(packet) {
        // Process RTP packet
        console.log('Handling RTP packet:', packet);
        let rtpPacketParsed  = parseRTPPacket(packet);
        console.log('--- rtpPacketParsed:', rtpPacketParsed);
      }
      
     handleRtcpPacket(packet) {
        // Process RTCP packet
        console.log('Handling RTCP packet:', packet);
        let parsedRtcpPacket = parseRTCPPacket(packet);
        console.log("Parsed rtcp packet : ", parsedRtcpPacket)
      }

    streamMediaFile(clientId, filePath) {
        const client = this.clients[clientId];
        const stream = fs.createReadStream(filePath, { highWaterMark: 1400 });
    //   this.rtspClient.on("data", (channel, data, packet) => {
    //         console.log("RTP:", "Channel=" + channel, "TYPE=" + packet.payloadType, "ID=" + packet.id, "TS=" + packet.timestamp, "M=" + packet.marker);
    //       if(channel == this.h264Details.rtpChannel){
    //          this.rtpServer.send(packet, 0, packet.length, client.rtpPort, 'localhost', (err) => {
    //                     if (err) console.error('Error sending RTP packet:', err);
    //                 });
    //       }
           
    //     });
    //   this.rtspClient.on("data", (chunk) => {
    //     const rtpPacket = this.createRtpPacket(chunk);
    //         this.rtpServer.send(rtpPacket, 0, rtpPacket.length, client.rtpPort, 'localhost', (err) => {
    //             if (err) console.error('Error sending RTP packet:', err);
    //         });
           
    //     });
        stream.on('data', async (chunk) => {
            const rtpPacket :any = await this.createRtpPacket(chunk);
            this.rtpServer.send(rtpPacket, 0, rtpPacket.length, client.rtpPort, 'localhost', (err) => {
                if (err) console.error('Error sending RTP packet:', err);
            });
        });
    
        stream.on('end', () => {
            console.log(`Finished streaming media file to ${clientId}`);
        });
    
        stream.on('error', (err) => {
            console.error(`Error streaming media file to ${clientId}: ${err.message}`);
        });
    }
  
     createRtpPacket(data) {
        // const rtpHeader = Buffer.alloc(12); // RTP header is 12 bytes
        // // Set RTP header fields
        // rtpHeader[0] = 0x80; // Version 2
        // rtpHeader[1] = 96;   // Payload type
        // rtpHeader.writeUInt16BE(this.rtpSequenceNumber++, 2); // Sequence number
        // rtpHeader.writeUInt32BE(this.rtpTimestamp, 4); // Timestamp
        // rtpHeader.writeUInt32BE(0x12345678, 8); // SSRC (arbitrary value)
    
        // // Increment the timestamp for the next packet
        // this.rtpTimestamp += 3600; // Increment by some value (depends on the media)
    
        // const rtpPacket = Buffer.concat([rtpHeader, data]);
        // return rtpPacket;


        const header = Buffer.alloc(4);
        header[0] = 0x24; // ascii $
        header[1] = 96;
        header[2] = (data.length >> 8) & 0xff;
        header[3] = (data.length >> 0) & 0xff;
    
        const rtpPacket = Buffer.concat([header, data]);
        return rtpPacket;

        // ????

    // let index = 0;

    // // $
    // const PACKET_START = 0x24;
    // // R
    // const RTSP_HEADER_START = 0x52;
    // // /n
    // const ENDL = 10;

    // while (index < data.length) {
    //   // read RTP or RTCP packet
    //   if (
    //     this.readState == ReadStates.SEARCHING &&
    //     data[index] == PACKET_START
    //   ) {
    //     this.messageBytes = [data[index]];
    //     index++;

    //     this.readState = ReadStates.READING_RAW_PACKET_SIZE;
    //   } else if (this.readState == ReadStates.READING_RAW_PACKET_SIZE) {
    //     // accumulate bytes for $, channel and length
    //     this.messageBytes.push(data[index]);
    //     index++;

    //     if (this.messageBytes.length == 4) {
    //       this.rtspPacketLength =
    //         (this.messageBytes[2] << 8) + this.messageBytes[3];

    //       if (this.rtspPacketLength > 0) {
    //         this.rtspPacket = new Buffer(this.rtspPacketLength);
    //         this.rtspPacketPointer = 0;
    //         this.readState = ReadStates.READING_RAW_PACKET;
    //       } else {
    //         this.readState = ReadStates.SEARCHING;
    //       }
    //     }
    //   } else if (this.readState == ReadStates.READING_RAW_PACKET) {
    //     this.rtspPacket[this.rtspPacketPointer++] = data[index];
    //     index++;

    //     if (this.rtspPacketPointer == this.rtspPacketLength) {
    //       const packetChannel = this.messageBytes[1];
    //       if ((packetChannel & 0x01) === 0) {
    //         // even number
    //         const packet = parseRTPPacket(this.rtspPacket);
    //         // this.emit("data", packetChannel, packet.payload, packet);
    //       }
    //       if ((packetChannel & 0x01) === 1) {
    //         // odd number
    //         const packet = parseRTCPPacket(this.rtspPacket);
    //         this.emit("controlData", packetChannel, packet);
    //         const receiver_report = this._emptyReceiverReport();
    //         this._sendInterleavedData(packetChannel, receiver_report);
    //       }
    //       this.readState = ReadStates.SEARCHING;
    //     }
    //     // read response data
    //   } else if (
    //     this.readState == ReadStates.SEARCHING &&
    //     data[index] == RTSP_HEADER_START
    //   ) {
    //     // found the start of a RTSP rtsp_message
    //     this.messageBytes = [data[index]];
    //     index++;

    //     this.readState = ReadStates.READING_RTSP_HEADER;
    //   } else if (this.readState == ReadStates.READING_RTSP_HEADER) {
    //     // Reading a RTSP message.

    //     // Add character to the messageBytes
    //     // Ignore /r (13) but keep /n (10)
    //     if (data[index] != 13) {
    //       this.messageBytes.push(data[index]);
    //     }
    //     index++;

    //     // if we have two new lines back to back then we have a complete RTSP command,
    //     // note we may still need to read the Content Payload (the body) e.g. the SDP
    //     if (
    //       this.messageBytes.length >= 2 &&
    //       this.messageBytes[this.messageBytes.length - 2] == ENDL &&
    //       this.messageBytes[this.messageBytes.length - 1] == ENDL
    //     ) {
    //       // Parse the Header

    //       const text = String.fromCharCode.apply(null, this.messageBytes);
    //       const lines = text.split("\n");

    //       this.rtspContentLength = 0;
    //       this.rtspStatusLine = lines[0];
    //       this.rtspHeaders = {};

    //       lines.forEach((line) => {
    //         const indexOf = line.indexOf(":");

    //         if (indexOf !== line.length - 1) {
    //           const key = line.substring(0, indexOf).trim();
    //           const data = line.substring(indexOf + 1).trim();

    //           this.rtspHeaders[key] =
    //             key != "Session" && data.match(/^[0-9]+$/)
    //               ? parseInt(data, 10)
    //               : data;

    //           // workaround for buggy Hipcam RealServer/V1.0 camera which returns Content-length and not Content-Length
    //           if (key.toLowerCase() == "content-length") {
    //             this.rtspContentLength = parseInt(data, 10);
    //           }
    //         }
    //       });

    //       // if no content length, there there's no media headers
    //       // emit the message
    //       if (!this.rtspContentLength) {
    //         this.emit("log", text, "S->C");

    //         this.emit("response", this.rtspStatusLine, this.rtspHeaders, []);
    //         this.readState = ReadStates.SEARCHING;
    //       } else {
    //         this.messageBytes = [];
    //         this.readState = ReadStates.READING_RTSP_PAYLOAD;
    //       }
    //     }
    //   } else if (
    //     this.readState == ReadStates.READING_RTSP_PAYLOAD &&
    //     this.messageBytes.length < this.rtspContentLength
    //   ) {
    //     // Copy data into the RTSP payload
    //     this.messageBytes.push(data[index]);
    //     index++;

    //     if (this.messageBytes.length == this.rtspContentLength) {
    //       const text = String.fromCharCode.apply(null, this.messageBytes);
    //       const mediaHeaders = text.split("\n");

    //       // Emit the RTSP message
    //       this.emit(
    //         "log",
    //         String.fromCharCode.apply(null, this.messageBytes) + text,
    //         "S->C"
    //       );

    //       this.emit(
    //         "response",
    //         this.rtspStatusLine,
    //         this.rtspHeaders,
    //         mediaHeaders
    //       );
    //       this.readState = ReadStates.SEARCHING;
    //     }
    //   } else {
    //     // unexpected data
    //     throw new Error(
    //       "Bug in RTSP data framing, please file an issue with the author with stacktrace."
    //     );
    //   }
    // } // end while
//   }


    }

    separateSdpAndHeaders(describeRes) {
        // Split the response into headers and SDP based on double newlines
        const [headersPart, sdpPart] = describeRes.split("\r\n\r\n");
    
        // Further split headers into individual header lines
        const headersLines = headersPart.split("\n");
    
        // Create an object to hold the headers
        const headers = {};
    
        // Populate the headers object
        headersLines.forEach(line => {
            const [key, value] = line.split(": ", 2);
            if (key && value) {
                headers[key.trim()] = value.trim();
            }
        });
    
        // Return the headers and SDP parts
        return {
            headers: headers,
            sdp: sdpPart.trim()
        };
    }
    

    parseRTSPResponse(response:any) {
    // Split the response into lines
    const lines = response.split('\n');

    // Initialize objects to hold general headers and media headers
    let headers :any= {};
    let mediaHeaders :any = [];
    let isMediaSection = false;

    lines.forEach((line:any) => {
        line = line.trim();
        if (line === '') return;

        // Detect the start of the media section
        if (line.startsWith('v=') || line.startsWith('o=') || line.startsWith('s=') ||
            line.startsWith('i=') || line.startsWith('c=') || line.startsWith('b=') ||
            line.startsWith('t=') || line.startsWith('a=') || line.startsWith('m=')) {
            isMediaSection = true;
        }

        if (isMediaSection) {
            mediaHeaders.push(line + '\r');
        } else {
            // Parse the general headers
            const headerParts = line.split(': ');
            if (headerParts.length === 2) {
                headers[headerParts[0]] = headerParts[1];
            } else {
                headers[''] = headerParts[0]; // The status line
            }
        }
    });

    // Add an empty string at the end of media headers as required
    mediaHeaders.push('');

    // Return the structured response
    return {
            headers: headers,
            mediaHeaders: mediaHeaders
    };
}

//  parseRTSPSetupRequest(request) {
//     const result = {
//       rtspStreamUrl: null,
//       transport: null,
//       session: null
//     };
  
//     // Split the request into lines
//     const lines = request.split('\n');
  
//     // Extract the RTSP stream URL from the first line
//     const requestLine = lines[0].trim();
//     const matchUrl = requestLine.match(/^SETUP (.+) RTSP\/1\.0$/);
//     if (matchUrl) {
//       result.rtspStreamUrl = matchUrl[1];
//     }
  
//     // Extract Transport header
//     const transportLine = lines.find(line => line.startsWith('Transport: '));
//     if (transportLine) {
//       result.transport = transportLine.split('Transport: ')[1].trim();
//     }
  
//     // Extract Session header (if present)
//     const sessionLine = lines.find(line => line.startsWith('Session: '));
//     if (sessionLine) {
//       result.session = sessionLine.split('Session: ')[1].trim();
//     }
  
//     return result;
//   }
  


}

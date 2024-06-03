import { Injectable } from '@nestjs/common';
import * as net from 'net';
import { v4 as uuidv4 } from 'uuid';
import * as dgram from "dgram";
import * as fs from 'fs'
import { parse as urlParse } from "url";
import { EventEmitter } from "events";
import * as crypto from "crypto";
import {
    parseRTPPacket,
    parseRTCPPacket,
    getMD5Hash,
    Transport,
    parseTransport,
    generateSSRC,
  } from "../../lib/util";
  
import * as transform from "sdp-transform";
const RTP_AVP = "RTP/AVP";

const STATUS_OK = 200;
const STATUS_UNAUTH = 401;
type Detail = {
    codec: string;
    mediaSource: ({ // cannot work out how to pull this type in
                  type: string;
                  port: number;
                  protocol: string;
                  payloads?: string | undefined;
                  } & any); // get Type from the interface
    transport: Transport['parameters']; // get Type from the interface
    isH264: boolean; // legacy API
    rtpChannel: number;
    rtcpChannel: number;
  };
  const WWW_AUTH = "WWW-Authenticate";
  const WWW_AUTH_REGEX = new RegExp('([a-zA-Z]+)\\s*=\\s*"?((?<=").*?(?=")|.*?(?=\\s*,?\\s*[a-zA-Z]+\\s*=)|.+[^\\s])', "g");
    
  enum ReadStates {
    SEARCHING,
    READING_RTSP_HEADER,
    READING_RTSP_PAYLOAD,
    READING_RAW_PACKET_SIZE,
    READING_RAW_PACKET,
  }
  
  type Connection = "udp" | "tcp";
  
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
export class RtspclientService extends EventEmitter{
    
public client:any;
public host:string;
public port :number = 554;
public username :string;
password :string;
path:string;
details: Detail[] = [];
cseq = 0;
public rtspExtStatus :string ='connected';
headers: { [key: string]: string };

isConnected = false;
closed = false;

// These are all set in #connect or #_netConnect.

_url?: string;
_client?: net.Socket;
_cSeq = 0;
_unsupportedExtensions?: string[];
// Example: 'SessionId'[';timeout=seconds']
_session?: string;
_keepAliveID?: NodeJS.Timeout;
_nextFreeInterleavedChannel = 0;
_nextFreeUDPPort = 5000;
tcpSocket: net.Socket = new net.Socket();
setupResult: Array<Detail> = [];
    private _onData: any;

// async connect(rtspUrl:string){
//     const parsedUrl = new URL(rtspUrl);

//     this.username = decodeURIComponent(parsedUrl.username);
//     this.password = decodeURIComponent(parsedUrl.password);
//     this.host = parsedUrl.hostname;
//     this.port  = parseInt(parsedUrl.port) || 554;
//     console.log("host --- : ", this.host);
//     console.log("port : ", this.port);
//     console.log("password : ", this.password);
//     // console.log("username : ", username);
//     this.path = `rtsp://${this.host}`+ parsedUrl.pathname + parsedUrl.search;
//    this.client = net.createConnection(this.port, this.host, async () => {
//         console.log('Connected to RTSP server');
       
//         try {
//           let response :any = await this.sendRtspCommand(this.client, "OPTIONS", this.path, {});
//           console.log("OPTIONS response:", response);
    
//           if (response.includes("401 Unauthorized")) {
//             const authType = response.match(/WWW-Authenticate: (\w+)/)[1];
//             let authHeader;
    
//             if (authType === "Digest") {
//               authHeader = this.handleDigestAuth(response, "OPTIONS", this.path);
//             } else if (authType === "Basic") {
//               const base64Credentials = Buffer.from(
//                 `${this.username}:${this.password}`
//               ).toString("base64");
//               authHeader = `Basic ${base64Credentials}`;
//             }
    
//             response = await this.sendRtspCommand(this.client, "OPTIONS", this.path, {
//               Authorization: authHeader,
//             });
//             console.log("OPTIONS response with auth:", response);
//           }

//            response = await this.sendRtspCommand(this.client, "DESCRIBE", this.path, {
//             Accept: "application/sdp",
//           });
//         }catch(err){
//            console.log('Error to connect with rtsp url : ', err);
//            this.client.close()
//         }
//    });
    
//    return this.client;
// }

async connect(url: string, {keepAlive = true,connection = "udp"}: { keepAlive: boolean; connection?: Connection } = {
        keepAlive: true,
        connection: "udp",
      }
  ): Promise<Detail[]> {
  
    const parsedUrl = new URL(url);

    const username = decodeURIComponent(parsedUrl.username);
    const password = decodeURIComponent(parsedUrl.password);
    if(username){
        this.username = username;
    }
    if(password){
        this.password = password;
    }
    const hostname = parsedUrl.hostname;
    const port : number = parseInt(parsedUrl.port) || 554;
    console.log("host : ", hostname);
    console.log("port : ", port);
    console.log("password : ", password);
    // console.log("username : ", username);
     this._url = `rtsp://${hostname}`+ parsedUrl.pathname + parsedUrl.search;
    if (!hostname) {
      throw new Error("URL parsing error in connect method.");
    }

    const details: Detail[] = [];

    await this._netConnect(hostname, port);
    await this.request("OPTIONS");

    const describeRes = await this.request("DESCRIBE", {
      Accept: "application/sdp",
    });
    if (!describeRes || !describeRes.mediaHeaders) {
      throw new Error(
        "No media headers on DESCRIBE; RTSP server is broken (sanity check)"
      );
    }

    // For now, only RTP/AVP is supported.
    const { media } = transform.parse(describeRes.mediaHeaders.join("\r\n"));

    // Loop over the Media Streams in the SDP looking for Video or Audio
    // In theory the SDP can contain multiple Video and Audio Streams. We only want one of each type
    let hasVideo = false;
    let hasAudio = false;
    let hasMetaData = false;
    let hasBackchannel = false;

    for (let x = 0; x < media.length; x++) {
      let needSetup = false;
      let codec = "";
      const mediaSource = media[x];


      // RFC says "If none of the direction attributes ("sendonly", "recvonly", "inactive", and "sendrecv") are present,
      // the "sendrecv" SHOULD be assumed
      if (mediaSource.direction == undefined) mediaSource.direction = "sendrecv"; //  Wowza does not send 'direction'

      if (
        mediaSource.type === "video" &&
        mediaSource.protocol === RTP_AVP &&
        mediaSource.rtp[0].codec === "H264"
      ) {
        this.emit("log", "H264 Video Stream Found in SDP", "");
        if (hasVideo == false) {
          needSetup = true;
          hasVideo = true;
          codec = "H264";
        }
      }

      if (
        mediaSource.type === "video" &&
        mediaSource.protocol === RTP_AVP &&
        mediaSource.rtp[0].codec === "H265"
      ) {
        this.emit("log", "H265 Video Stream Found in SDP", "");
        if (hasVideo == false) {
          needSetup = true;
          hasVideo = true;
          codec = "H265";
        }
      }


      if (
        mediaSource.type === "audio" &&
        (mediaSource.direction === "recvonly" || mediaSource.direction === "sendrecv") &&
        mediaSource.protocol === RTP_AVP &&
        mediaSource.rtp[0].codec.toLowerCase() === "mpeg4-generic" && // (RFC examples are lower case. Axis cameras use upper case)
        mediaSource.fmtp[0].config.includes("AAC")
      ) {
        this.emit("log", "AAC Audio Stream Found in SDP", "");
        if (hasAudio == false) {
          needSetup = true;
          hasAudio = true;
          codec = "AAC";
        }
      }

      if (mediaSource.type === "audio" &&
        mediaSource.direction === "sendonly" &&
        mediaSource.protocol === RTP_AVP) {
        this.emit("log", "Audio backchannel Found in SDP", "");
        if (hasBackchannel == false) {
          needSetup = true;
          hasBackchannel = true;
          codec = mediaSource.rtp[0].codec;
        }
      }

      if (
        mediaSource.type === "application" &&
        mediaSource.protocol === RTP_AVP &&
        mediaSource.rtp[0].codec.toLowerCase() === "vnd.onvif.metadata"
      ) {
        this.emit("log", "ONVIF Meta Data Found in SDP", "");
        if (hasMetaData == false) {
          needSetup = true;
          hasMetaData = true;
          codec = "vnd.onvif.metadata";
        }
      }

      if (needSetup) {
        let streamurl = "";
        // The 'control' in the SDP can be a relative or absolute uri
        if (mediaSource.control) {
          if (mediaSource.control.toLowerCase().startsWith("rtsp://")) {
            // absolute path
            streamurl = mediaSource.control;
          } else {
            // relative path
            streamurl = this._url + "/" + mediaSource.control;
          }
        }

        // Perform a SETUP on the streamurl
        // either 'udp' RTP/RTCP packets
        // or with 'tcp' RTP/TCP packets which are interleaved into the TCP based RTSP socket
        let setupRes;
        let rtpChannel;
        let rtcpChannel;
        let rtpReceiver: dgram.Socket|null = null; // UDP mode init value
        let rtcpReceiver: dgram.Socket|null = null; // UDP mode init value

        if (connection === "udp") {
          // Create a pair of UDP listeners, even numbered port for RTP
          // and odd numbered port for RTCP

          rtpChannel = this._nextFreeUDPPort;
          rtcpChannel = this._nextFreeUDPPort + 1;
          this._nextFreeUDPPort += 2;

          const rtpPort = rtpChannel;
          rtpReceiver = dgram.createSocket("udp4");

          rtpReceiver.on("message", (buf, remote) => {
            const packet = parseRTPPacket(buf);
            this.emit("data", rtpPort, packet.payload, packet);
          });

          const rtcpPort = rtcpChannel;
          rtcpReceiver = dgram.createSocket("udp4");

        //   rtcpReceiver.on("message", (buf, remote) => {
        //     const packet = parseRTCPPacket(buf);
        //     this.emit("controlData", rtcpPort, packet);

        //     const receiver_report = this._emptyReceiverReport();
        //     this._sendUDPData(remote.address, remote.port, receiver_report);
        //   });

          // Block until both UDP sockets are open.

          await new Promise((resolve) => {
            rtpReceiver?.bind(rtpPort, () => resolve({}));
          });

          await new Promise((resolve) => {
            rtcpReceiver?.bind(rtcpPort, () => resolve({}));
          });

          const setupHeader = {
            Transport: `RTP/AVP;unicast;client_port=${rtpPort}-${rtcpPort}`,
          };
          if (this._session)
            Object.assign(setupHeader, { Session: this._session });
          setupRes = await this.request("SETUP", setupHeader, streamurl);
        } else if (connection === "tcp") {
          // channel 0, RTP
          // channel 1, RTCP

          rtpChannel = this._nextFreeInterleavedChannel;
          rtcpChannel = this._nextFreeInterleavedChannel + 1;
          this._nextFreeInterleavedChannel += 2;

          const setupHeader = {
            Transport: `RTP/AVP/TCP;interleaved=${rtpChannel}-${rtcpChannel}`,
          };
          if (this._session)
            Object.assign(setupHeader, { Session: this._session }); // not used on first SETUP
          setupRes = await this.request("SETUP", setupHeader, streamurl);
        } else {
          throw new Error(
            `Connection parameter to RTSPClient#connect is ${connection}, not udp or tcp!`
          );
        }

        if (!setupRes) {
          throw new Error(
            "No SETUP response; RTSP server is broken (sanity check)"
          );
        }

        const { headers } = setupRes;

        if (!headers.Transport) {
          throw new Error(
            "No Transport header on SETUP; RTSP server is broken (sanity check)"
          );
        }

        const transport = parseTransport(headers.Transport);
        if (
          transport.protocol !== "RTP/AVP/TCP" &&
          transport.protocol !== "RTP/AVP"
        ) {
          throw new Error(
            "Only RTSP servers supporting RTP/AVP(unicast) or RTP/ACP/TCP are supported at this time."
          );
        }

        // Patch from zoolyka (Zoltan Hajdu).
        // Try to open a hole in the NAT router (to allow incoming UDP packets)
        // by send a UDP packet for RTP and RTCP to the remote RTSP server.
        // Note, Roger did not have a router that needed this so the feature is untested.
        // May be better to change the RTCP message to a Receiver Report, leaving the RTP message as zero bytes
        if (connection === "udp" && transport && rtpReceiver && rtcpReceiver) {
          rtpReceiver.send(Buffer.from(''), Number(transport.parameters["server_port"].split("-")[0]), hostname);
          rtcpReceiver.send(Buffer.from(''), Number(transport.parameters["server_port"].split("-")[1]), hostname);
        }

        if (headers.Unsupported) {
          this._unsupportedExtensions = headers.Unsupported.split(",");
        }

        if (headers.Session) {
          this._session = headers.Session.split(";")[0];
        }

        const detail: Detail = {
          codec,
          mediaSource,
          transport: transport.parameters,
          isH264: codec === "H264",
          rtpChannel,
          rtcpChannel,
        };

        details.push(detail);
      } // end if (needSetup)
    } // end for loop, looping over each media stream

    if (keepAlive) {
      // Start a Timer to send OPTIONS every 20 seconds to keep stream alive
      // using the Session ID
      this._keepAliveID = setInterval(() => {
        this.request("OPTIONS", { Session: this._session });
        //        this.request("OPTIONS");
      }, 20 * 1000);
    }

    this.setupResult = details;
    return details;
  }

async callExtDescribe(){
    let response = await this.sendRtspCommand(this.client, "DESCRIBE", this.path, {
        Accept: "application/sdp",
      });
      console.log("DESCRIBE response:", response);
    //   let describeRes = await this.parseRTSPDResponse(response);
    //   console.log("describeRes : ", describeRes);
    //   const { media } = transform.parse(describeRes.mediaHeaders.join("\r\n"));
    //   console.log("media : ", media);
    return response;

}

sendRtspCommand(socket, method, uri, headers, body = '') {
    return new Promise((resolve, reject) => {
        let request = `${method} ${uri} RTSP/1.0\r\n`;
        request += `CSeq: ${this.getNextCSeq()}\r\n`;
        for (const header in headers) {
            request += `${header}: ${headers[header]}\r\n`;
        }
        request += `User-Agent: NodeRTSPClient\r\n`;
        request += `Content-Length: ${body.length}\r\n`;
        request += '\r\n';
        request += body;

        console.log('Sending request:\n', request);

        socket.write(request, 'utf8', (err) => {
            if (err) {
                reject(err);
            }
        });

        socket.once('data', (data) => {
            resolve(data.toString());
        });
    });
}


getNextCSeq() {
    return ++this.cseq;
}
parseAuthHeader(header) {
    const authDetails = {};
    const parts = header.match(/([a-z]+)="([^"]+)"/gi);
    parts.forEach(part => {
        const [key, value] = part.split('=');
        authDetails[key.toLowerCase()] = value.replace(/"/g, '');
    });
    return authDetails;
}

generateDigestAuth(username, password, realm, nonce, uri, method, qop, nc, cnonce) {
    const ha1 = crypto.createHash('md5').update(`${username}:${realm}:${password}`).digest('hex');
    const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');
    const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`).digest('hex');

    return `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}", qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
}

handleDigestAuth(response, method, uri) {
    const authHeader = response.match(/WWW-Authenticate: (.+)/)[1];
    const authDetails :any = this.parseAuthHeader(authHeader);

    const qop = 'auth';
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');

    return this.generateDigestAuth(this.username, this.password, authDetails.realm, authDetails.nonce, uri, method, qop, nc, cnonce);
}


 parseRTSPDResponse(response:any) {
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

request(
    requestName: string,
    headersParam: Headers = {},
    url?: string
  ): Promise<{ headers: Headers; mediaHeaders?: string[] } | void> {
    if (!this._client) {
      return Promise.resolve();
    }

    const id = ++this._cSeq;
    // mutable via string addition
    let req = `${requestName} ${url || this._url} RTSP/1.0\r\nCSeq: ${id}\r\n`;

    const headers = {
      ...this.headers,
      ...headersParam,
    };

    // NOTE:
    // If we cache the Authenitcation Type (Direct or Basic) then we could
    // re-compute an Authorization Header here and include in the RTSP Command
    // This would make connections a faster with fewer round-trips to the RTSP Server

    req += Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}\r\n`)
      .join("");

    console.log("log", req, "C->S");
    // Make sure to add an empty line after the request.
    this._client.write(`${req}\r\n`);

    return new Promise((resolve, reject) => {
      const responseHandler = (
        responseName: string,
        resHeaders: Headers,
        mediaHeaders: string[]
      ) => {
        const firstAnswer: string = String(resHeaders[""]) || "";
        if (firstAnswer.indexOf("401") >= 0 && 'Authorization' in headers) {
          // If the RTSP Command we sent included an Authorization and we have 401 error, then reject()
          reject(new Error(`Bad RTSP credentials!`));
          return;
        }
        if (resHeaders.CSeq !== id) {
          return;
        }

        this.removeListener("response", responseHandler);

        const statusCode = parseInt(responseName.split(" ")[1]);

        if (statusCode === STATUS_OK) {
          if (mediaHeaders.length > 0) {
            resolve({
              headers: resHeaders,
              mediaHeaders,
            });
          } else {
            resolve({
              headers: resHeaders,
            });
          }
        } else {
          const authHeader = resHeaders[WWW_AUTH];

          // We have status code unauthenticated.
          if (statusCode === STATUS_UNAUTH && authHeader) {
            const type = authHeader.split(" ")[0];

            // Get auth properties from WWW_AUTH header.
            let realm = "";
            let nonce = "";

            let match = WWW_AUTH_REGEX.exec(authHeader);
            while (match != null) {
              const prop = match[1];

              if (prop == "realm" && match[2]) {
                realm = match[2];
              }

              if (prop == "nonce" && match[2]) {
                nonce = match[2];
              }

              match = WWW_AUTH_REGEX.exec(authHeader);
            }

            // mutable, corresponds to Authorization header
            let authString = "";

            if (type === "Digest") {
              // Digest Authentication

              const ha1 = getMD5Hash(
                `${this.username}:${realm}:${this.password}`
              );
              const ha2 = getMD5Hash(`${requestName}:${this._url}`);
              const ha3 = getMD5Hash(`${ha1}:${nonce}:${ha2}`);

              authString = `Digest username="${this.username}",realm="${realm}",nonce="${nonce}",uri="${this._url}",response="${ha3}"`;
            } else if (type === "Basic") {
              // Basic Authentication
              // https://xkcd.com/538/
              const b64 = new Buffer(
                `${this.username}:${this.password}`
              ).toString("base64");
              authString = `Basic ${b64}`;
            }

            Object.assign(headers, {
              Authorization: authString,
            });

            resolve(this.request(requestName, headers, url)); // Call this.request with Authorized request
            return;
          }

          reject(new Error(`Bad RTSP status code ${statusCode}!`));
          return;
        }
      };

      this.on("response", responseHandler);
    });
  }

  _netConnect(hostname: string, port: number): Promise<this> {
    return new Promise((resolve, reject) => {
      // Set after listeners defined.

      const errorListener = (err: any) => {
        client.removeListener("error", errorListener);
        reject(err);
      };

      const closeListener = () => {
        client.removeListener("close", closeListener);
        this.close(true);
      };

      const responseListener = (responseName: string, headers: Headers) => {
        const name = responseName.split(" ")[0];

        if (name.indexOf("RTSP/") === 0) {
          return;
        }

        if (name === "REDIRECT" || name === "ANNOUNCE") {
        //   this.respond("200 OK", { CSeq: headers.CSeq });
        }

        if (name === "REDIRECT" && headers.Location) {
          this.close();
          this.connect(headers.Location);
        }
      };

      const client = net.connect(port, hostname, () => {
        this.isConnected = true;
        this._client = client;

        client.removeListener("error", errorListener);

        this.on("response", responseListener);
        resolve(this);
      });

    //   client.on("data", this._onData.bind(this));
      client.on("error", errorListener);
      client.on("close", closeListener);
      this.tcpSocket = client;
    });
  }

  async close(isImmediate = false): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    if (!this._client) {
      return;
    }
    
    if (!isImmediate) {
      await this.request("TEARDOWN", {
        Session: this._session,
      });
    }

    this._client.end();
    this.removeAllListeners("response");

    if (this._keepAliveID != undefined) {
      clearInterval(this._keepAliveID);
      this._keepAliveID = undefined;
    }

    this.isConnected = false;
    this._cSeq = 0;
  }

}

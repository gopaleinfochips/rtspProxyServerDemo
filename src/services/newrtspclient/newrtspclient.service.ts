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
import { Observable, Observer } from 'rxjs';

interface observerEmitData  {
    type : string;
    message : string;
    data : any;
}
@Injectable()
export class NewrtspclientService {
    private connectionObserver: Observer<observerEmitData>;
    public connectionStatus$: Observable<observerEmitData>;
  
    public client: net.Socket;
    public host: string;
    public port: number = 554;
    public username: string;
    password: string;
    path: string;
    // details: Detail[] = [];
    cseq = 0;
    public rtspExtStatus: string = 'connected';
    headers: { [key: string]: string };

    constructor() {
        this.connectionStatus$ = new Observable((observer) => {
            this.connectionObserver = observer;
          });
    }

    async connect(rtspUrl: string) {
        return new Promise((resolve, reject) => {
            try {
                const parsedUrl = new URL(rtspUrl);
                this.username = decodeURIComponent(parsedUrl.username);
                this.password = decodeURIComponent(parsedUrl.password);
                this.host = parsedUrl.hostname;
                this.port = parseInt(parsedUrl.port) || 554;
                this.path = `rtsp://${this.host}` + parsedUrl.pathname + parsedUrl.search;
                this.client = net.createConnection(this.port, this.host, async () => {
                    console.log('Connected to RTSP server');
                });

                this.client.on("error", (err) => {
                    console.error("RTSP connection error:", err);
                    let emitData : observerEmitData = {
                        type : 'error',
                        message : 'RTSP connection error',
                        data :err
                    } 
                    this.connectionObserver.next(emitData);
                  });
                  
                this.client.on("close", () => {
                    console.log("RTSP connection closed");
                    let emitData : observerEmitData = {
                        type : 'close',
                        message : 'RTSP connection closed',
                        data :''
                    } 
                    
                    this.connectionObserver.next(emitData);
                  });
                resolve(this.client);
            } catch (err) {
                console.error("RTSP connection error:", err);
                let emitData : observerEmitData = {
                    type : 'error',
                    message : 'RTSP connection error',
                    data :err
                } 
                this.connectionObserver.next(emitData);
                reject(err);
            }
        })

    }

    async sendOption(){
      return await this.sendRtspCommand(this.client, "OPTIONS", this.path);
    }
    
    async sendDescribe(){
        return await this.sendRtspCommand(this.client, "DESCRIBE", this.path, {
            Accept: "application/sdp",
          });
        //   console.log("DESCRIBE response:", response)
    }

    async sendSetup(streamurl, transport, session ){
        return await this.sendRtspCommand(this.client, "SETUP", streamurl, {
            Accept: "application/sdp",
            Transport: transport,
            Session: session,
          });
        //   console.log("DESCRIBE response:", response)
    }

    async sendPlay(streamurl, session, range ){
        return await this.sendRtspCommand(this.client, "PLAY",streamurl , {
            Accept: "application/sdp",
            Range: range ,
            Session: session,
          });
        //   console.log("DESCRIBE response:", response)
    }

    async sendPause(streamurl, session){
        return await this.sendRtspCommand(this.client, "PAUSE",streamurl , {
            Accept: "application/sdp",
            Session: session,
          });
        //   console.log("DESCRIBE response:", response)
    }
    async sendTeardown(){
        return await this.sendRtspCommand(this.client, "TEARDOWN", this.path, {
            Accept: "application/sdp",
          });
        //   console.log("DESCRIBE response:", response)
    }
    async sendRawPacket(data){
        return new Promise((resolve, reject) => {
             this.client.write(data), async (err) => {
              this.client.once("data", async (data) => {
                resolve(data.toString())
            });
            if(err){
                reject(err);
            }
        }
    });
        //   console.log("DESCRIBE response:", response)
    }

    async sendRtspCommand(client, method, uri, headers: any = {}, retry = true) {
        return new Promise((resolve, reject) => {
            const cSeq = ++this.cseq;
            const lines = [`${method} ${uri} RTSP/1.0`, `CSeq: ${cSeq}`];

            for (const key in headers) {
                lines.push(`${key}: ${headers[key]}`);
            }

            lines.push("\r\n");

            client.write(lines.join("\r\n"), async (err) => {
                if (err) return reject(err);

                client.once("data", async (data) => {
                    const response = data.toString();
                    if (retry && response.includes("401 Unauthorized")) {
                        const authType = response.match(/WWW-Authenticate: (\w+)/)[1];
                        if (authType === "Digest") {
                            const authInfo = {
                                realm: response.match(/realm="([^"]+)"/)[1],
                                nonce: response.match(/nonce="([^"]+)"/)[1]
                            };
                            const authHeader = this.generateDigestAuthHeader(authInfo, method, uri, this.username, this.password);
                            headers.Authorization = authHeader;

                            try {
                                const retryResponse = await this.sendRtspCommand(client, method, uri, headers, false);
                                resolve(retryResponse);
                            } catch (retryErr) {
                                reject(retryErr);
                            }
                        } else if (authType === "Basic") {
                            const base64Credentials = Buffer.from(`${this.username}:${this.password}`).toString("base64");
                            headers.Authorization = `Basic ${base64Credentials}`;
                            try {
                                const retryResponse = await this.sendRtspCommand(client, method, uri, headers, false);
                                resolve(retryResponse);
                            } catch (retryErr) {
                                reject(retryErr);
                            }
                        } else {
                            reject(new Error("Unsupported authentication method"));
                        }
                    } else {
                        resolve(response);
                    }
                });
            });
        });
    }

    md5(data: any) {
        return crypto.createHash('md5').update(data).digest('hex');
    }

    generateDigestAuthHeader(authInfo, method, uri, username, password) {
        const ha1 = this.md5(`${username}:${authInfo.realm}:${password}`);
        const ha2 = this.md5(`${method}:${uri}`);
        const response = this.md5(`${ha1}:${authInfo.nonce}:${ha2}`);
        return `Digest username="${username}", realm="${authInfo.realm}", nonce="${authInfo.nonce}", uri="${uri}", response="${response}"`;
    }




}

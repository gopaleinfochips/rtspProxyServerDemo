import { Injectable } from '@nestjs/common';
import * as net from 'net';
import { VideoStream } from './video-stream';

@Injectable()
export class RtspserverService {
  private server: net.Server;
  private videoStream: VideoStream;

  constructor() {
    this.videoStream = new VideoStream('samplevideo.mp4');
    this.server = net.createServer(this.handleConnection.bind(this));
  }

  start(port: number) {
    this.server.listen(port, () => {
      console.log(`RTSP server is listening on port ${port}`);
    });
  }

  handleConnection(socket: net.Socket) {
    socket.on('data', (data) => {
      const request = data.toString();
      console.log('Received request:', request);
      const lines = request.split('\r\n');
      const [method, url] = lines[0].split(' ');

      switch (method) {
        case 'OPTIONS':
          this.handleOptions(socket);
          break;
        case 'DESCRIBE':
          this.handleDescribe(socket, url);
          break;
        case 'SETUP':
          this.handleSetup(socket, url);
          break;
        case 'PLAY':
          this.handlePlay(socket, url);
          break;
        case 'TEARDOWN':
          this.handleTeardown(socket, url);
          break;
        default:
          console.log(`Unhandled method: ${method}`);
      }
    });
  }

  handleOptions(socket: net.Socket) {
    const response = [
      'RTSP/1.0 200 OK',
      'CSeq: 1',
      'Public: OPTIONS, DESCRIBE, SETUP, PLAY',
      '\r\n'
    ].join('\r\n');
    socket.write(response);
  }

  handleDescribe(socket: net.Socket, url: string) {
    const sdp = [
      'v=0',
      'o=- 0 0 IN IP4 127.0.0.1',
      's=No Name',
      'c=IN IP4 127.0.0.1',
      't=0 0',
      'a=tool:node-rtsp-server',
      'm=video 0 RTP/AVP 96',
      'a=rtpmap:96 H264/90000',
      '\r\n'
    ].join('\r\n');
    const response = [
      'RTSP/1.0 200 OK',
      'CSeq: 2',
      'Content-Type: application/sdp',
      `Content-Length: ${Buffer.byteLength(sdp)}`,
      '\r\n',
      sdp
    ].join('\r\n');
    socket.write(response);
  }

  handleSetup(socket: net.Socket, url: string) {
    const response = [
      'RTSP/1.0 200 OK',
      'CSeq: 3',
      'Transport: RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001',
      'Session: 12345678',
      '\r\n'
    ].join('\r\n');
    socket.write(response);
  }

  handlePlay(socket: net.Socket, url: string) {
    const response = [
      'RTSP/1.0 200 OK',
      'CSeq: 4',
      'Range: npt=0.000-',
      'Session: 12345678',
      '\r\n'
    ].join('\r\n');
    socket.write(response);

    this.videoStream.startStreaming();
  }
  handleTeardown(socket: net.Socket, url: string) {
    const response = [
        `200 OK`,
        `CSeq: 5`,

        '',
        ''
    ].join('\r\n');
    socket.write(response);
  }
}



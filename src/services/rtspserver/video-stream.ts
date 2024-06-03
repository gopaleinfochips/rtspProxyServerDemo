import * as fs from 'fs';
import * as dgram from 'dgram';

export class VideoStream {
  private filePath: string;
  private rtpServer: dgram.Socket;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.rtpServer = dgram.createSocket('udp4');
  }

  startStreaming() {
    const stream = fs.createReadStream(this.filePath, { highWaterMark: 4096 });
    stream.on('data', (chunk : Buffer) => {
      this.sendRtpPacket(chunk);
    });
  }

  sendRtpPacket(data: Buffer) {
    const rtpPacket = Buffer.alloc(12 + data.length);
    rtpPacket[0] = 0x80;
    rtpPacket[1] = 0x60;
    rtpPacket.writeUInt16BE(0, 2);
    rtpPacket.writeUInt32BE(0, 4);
    rtpPacket.writeUInt32BE(0, 8);
    data.copy(rtpPacket, 12);

    this.rtpServer.send(rtpPacket, 9000, '127.0.0.1', (err) => {
      if (err) console.error('Error sending RTP packet:', err);
    });
  }
}

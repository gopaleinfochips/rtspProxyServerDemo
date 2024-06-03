import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { RtspclientService } from './services/rtspclient/rtspclient.service';
import { MainServerService } from './services/main-server/main-server.service';
import { RtspserverService } from './services/rtspserver/rtspserver.service';;
import { NewrtspclientService } from './services/newrtspclient/newrtspclient.service';
// import RTSPClient from './services/rtspclient/RTSPClient';

@Module({
  imports: [],
  controllers: [AppController],
  providers: [AppService, RtspclientService, MainServerService, RtspserverService, NewrtspclientService],
})
export class AppModule {}

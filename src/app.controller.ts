import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { MainServerService } from './services/main-server/main-server.service';
import { RtspclientService } from './services/rtspclient/rtspclient.service';
import { RtspserverService } from './services/rtspserver/rtspserver.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService,
    // private mainServerService : MainServerService,
    private rtspClientService : RtspclientService,
    private rtspServer : RtspserverService
  ) {
  
   
    // this.rtspServer.start(8554);
  }

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }


  
}

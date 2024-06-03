import { Test, TestingModule } from '@nestjs/testing';
import { RtspserverService } from './rtspserver.service';

describe('RtspserverService', () => {
  let service: RtspserverService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RtspserverService],
    }).compile();

    service = module.get<RtspserverService>(RtspserverService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

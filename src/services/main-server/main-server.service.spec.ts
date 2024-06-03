import { Test, TestingModule } from '@nestjs/testing';
import { MainServerService } from './main-server.service';

describe('MainServerService', () => {
  let service: MainServerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MainServerService],
    }).compile();

    service = module.get<MainServerService>(MainServerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

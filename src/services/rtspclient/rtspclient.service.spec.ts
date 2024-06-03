import { Test, TestingModule } from '@nestjs/testing';
import { RtspclientService } from './rtspclient.service';

describe('RtspclientService', () => {
  let service: RtspclientService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RtspclientService],
    }).compile();

    service = module.get<RtspclientService>(RtspclientService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

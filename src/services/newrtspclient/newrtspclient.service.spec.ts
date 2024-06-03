import { Test, TestingModule } from '@nestjs/testing';
import { NewrtspclientService } from './newrtspclient.service';

describe('NewrtspclientService', () => {
  let service: NewrtspclientService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [NewrtspclientService],
    }).compile();

    service = module.get<NewrtspclientService>(NewrtspclientService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

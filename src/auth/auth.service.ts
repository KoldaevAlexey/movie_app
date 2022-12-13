import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { InjectModel } from 'nestjs-typegoose';
import { hash, getSalt, compare, genSalt } from 'bcryptjs';

import { UserModel } from 'src/user/user.model';
import { AuthDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>,
    private readonly jwtservice: JwtService,
  ) {}

  async login(dto: AuthDto) {
    return this.validateUser(dto);
  }

  async findUserEmail(dto: AuthDto) {
    return this.UserModel.findOne({ email: dto.email });
  }

  async register(dto: AuthDto) {
    const oldUser = await this.findUserEmail(dto);
    if (oldUser)
      throw new BadRequestException(
        'User with this email is already in the system',
      );

    const salt = await genSalt(10);

    const newUser = new this.UserModel({
      email: dto.email,
      password: await hash(dto.password, salt),
    });

    return newUser.save();
  }

  async validateUser(dto: AuthDto): Promise<UserModel> {
    const user = await this.findUserEmail(dto);
    if (!user) throw new UnauthorizedException('User not found');

    const isValidPassword = await compare(dto.password, (await user).password);
    if (!isValidPassword) throw new UnauthorizedException('Invalid password');

    return user;
  }

  async issueTokenPair(userId: string) {
    const data = { _id: userId };

    const refreshToken = await 
  }
}

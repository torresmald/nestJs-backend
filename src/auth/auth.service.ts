import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs'
import { LoginDto } from './dto/login-dto';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const {password, ...userData} = createUserDto
      const newUser = await new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData
      })
      return await newUser.save()
    } catch (error) {
      if(error.code == 11000){
        throw new BadRequestException(`Duplicated key ${Object.keys(error.keyValue)}`)
      }
    }
  }

  async login(loginDto: LoginDto) {
    const {email, password} = loginDto
    const user = await this.userModel.findOne({email})

    if(!user) return new UnauthorizedException('Unauthorized - email')

    if(!bcrypt.compareSync(password, user.password)) return new UnauthorizedException('Unauthorized - password')

    const {password:_, ...restUser} = user.toJSON()
    return {
      user: restUser,
      token: 'kjshdf'
    }

  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}

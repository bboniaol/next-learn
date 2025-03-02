import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import { authConfig } from './auth.config';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: false });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        if (!parsedCredentials.success) {
          console.error('验证失败:', parsedCredentials.error);
          throw new Error('Invalid credentials format');
        }

        try {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          

          if (!user) {
            console.error('用户不存在:', email);
            throw new Error('Invalid credentials');
          }
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (!passwordsMatch) {
            console.error('密码不匹配:', email);
            throw new Error('Invalid credentials');
          }

          return {
            id: user.id,
            name: user.name,
            email: user.email
          };
        } catch (error) {
          console.error('认证错误:', error);
          throw new Error('Invalid credentials');
        }
      },
    }),
  ],
});

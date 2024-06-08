# Token-based (Email & Password)

This guided tutorial is part of a series of articles on building an authenticated backend with TypeScript, Hono, PostgreSQL, and Prisma. In this first tutorial, we'll look at how to secure the REST API with password authentication using Prisma for token storage and implement authorization.

## What you will learn today

In this tutorial, you will explore the fundamental concepts of authentication and authorization, understand their distinctions, and learn how to implement email-based password authentication and authorization using JSON Web Tokens (JWT) with Hono to secure your REST API.
Specifically, you will develop the following aspects:

1. Password Authentication: Implement a sign-up and login system where users receive a unique token via email. Users complete the authentication process by sending the received token to the API, which then issues a long-lived JWT token granting access to authenticated API endpoints.
2. Authorization: Incorporate authorization logic to control which resources authenticated users can access and manipulate based on their roles or permissions.

## Prerequisites

### Assumed knowledge

This tutorial assumes a basic understanding of TypeScript, Node.js, and relational databases. If you're proficient in JavaScript but new to TypeScript, you can still follow along comfortably. The tutorial series will utilize PostgreSQL, but most of the concepts are applicable to other relational databases such as MySQL. Familiarity with REST principles is advantageous. Some prior knowledge of Prisma is required.

### Development environment

Ensure you have the following tools installed on your machine:

- [Bun](https://bun.sh/) v 1.x or later

If you're using Visual Studio Code, the Prisma extension is recommended for syntax highlighting, formatting, and other helpers.

## Clone the repository

The source code for the tutorial can be found on [GitHub].

To get started, clone the repository and install the dependencies:

```sh
git clone https://github.com/rubcstswe/web102-hono-auth-jwt-prisma.git
cd web102-hono-auth-jwt-prisma
bun install
```

!!! note

    The repository has already implemented a basic REST API with Hono and Prisma. The API includes a user model and a few endpoints to create, read, update, and delete users. The API is not secured and can be accessed without authentication.

## Data Model/Schema

The fundamental building block of the Prisma schema is [model](https://www.prisma.io/docs/orm/prisma-schema/data-model/models). Every model maps to a database table.

Here is a basic schema showing the basic bank account in a 1-n relationship to a user from the project repository that you have cloned:

```prisma title="schema.prisma" linenums="13"
model User {
  id      String    @id @default(uuid())
  email   String    @unique
  Account Account[]
}

model Account {
  id      String @id @default(uuid())
  userId  String
  user    User   @relation(fields: [userId], references: [id])
  balance Int    @default(0)
}
```

!!! note

    The `User` model has a one-to-many relationship with the `Account` model. A user can have multiple accounts, but an account belongs to only one user.

## REST API Endpoints

| Method | Endpoint                                        | Description                                                |
| :----- | :---------------------------------------------- | :--------------------------------------------------------- |
| `GET`  | `http://localhost:3000/:userId/account/balance` | Retrieves all accounts owned by the user with its' balance |

Where the user id is given as `7a038d5b-65aa-45c5-9f7e-c9b86a071099`

Let's build a http request to get the balance of the account of the user with the id `7a038d5b-65aa-45c5-9f7e-c9b86a071099`

### Request

```http

http://localhost:3000/7a038d5b-65aa-45c5-9f7e-c9b86a071099/account/balance

```

### Response

```json
{
  "data": {
    "Account": [
      {
        "balance": 0,
        "id": "75a34064-f8c4-4a7e-90dd-4958c452fbf4"
      }
    ]
  }
}
```

!!! question

    Should anyone be able to access and view any user's bank account balance?

    If you realised that the API is not secured and can be accessed without authentication, you are right! 

    Technically, only the user who owns the account should be able to access the account balance.

    In the next step, we will implement a password authentication system using Prisma for token storage and implement authorization.

## Authentication and authorization concepts

Before going into the implementation, let's explore the concepts of authentication and authorization. While these terms are often used interchangeably, they serve distinct purposes and work together to secure applications.

**Authentication** is the process of verifying a user's identity. In other words, it answers the question "Who are you?" One real-world example of authentication is a valid passport. By matching your appearance with the official document's photo and details (which are difficult to forge), your passport authenticates that you are the person you claim to be. When you arrive at the airport, presenting your passport allows you to proceed through security.

On the other hand, **authorization** is the process of verifying what resources or actions a user is permitted to access or perform. It answers the question "What are you allowed to do?" Continuing with the airport example, authorization occurs when you present your boarding pass (which is typically scanned and verified against the flight's passenger database). The ground attendant then authorizes you to board the flight.

In summary, authentication establishes identity, while authorization determines access privileges. These complementary processes work together to secure applications and ensure that only authenticated users can access the resources and perform the actions they are authorized for.

### Authentication in web applications

Web applications typically use a username and password to authenticate users. If a valid username and password are verified and correct, the server can verify that you're the user you claim to be because the password is supposed to be only known to you and the application.

!!! note

    Web applications that use username/password authentication rarely store the password in clear text in the database. Instead, they use a technique called hashing to store a hash of the password. This allows the backend to verify the password without knowing it.

    A hash function is a mathematical function that takes arbitrary input and always generates the same fixed-length string/number given the same input. The power of hash function lies in that you can go from a password to a hash but not from a hash to a password.

    This allows verifying the password submitted by the user without storing the actual password. Storing password hashes protects users in the case of breached accounts.

### Authentication and signup/login flow

Email-based password authentication is a two-step process.

1. **Register**: The user provides an email and password to create an account. The server stores the user's email and a hashed password in the database.
   
2. **Login**: The user provides their email and password to authenticate themselves. The server verifies the email and password against the stored hash. If the credentials are correct, the server issues a long-lived JWT token that the user can use to access authenticated API endpoints.

A successful authentication flow will look as follows:

``` mermaid
sequenceDiagram
  autonumber
  User->>Server: register {email, password}
  Server->>Database: Create user (if new/doesnt exist)
  Server-->>User: HTTP 200 OK {message: "User created successfully"}
  User->>Server: login {email, password}
  Server-->>Database: Verify if email is in the database and the password matches the stored hash
  Server-->>User: JWT token sent back in authorization header
  User->>Server: User passes JWT auth token in the authorization header in subsequent requests
```

1. The user calls the /register endpoint in the API with the email and password in the payload to begin the registration process.
2. If the email is new, the user is created in the User table and the password is hashed and stored in the database.
3. he user calls the /login endpoint in the API with the email and password in the payload to begin the authentication process.
4. The backend validates the email and password sent by the user. If the email exists and the password matches the stored hash, the user is authenticated.
5. The JWT token is sent back to the user via the Authorization header.


**Authentication token**: A JWT token with tokenId in its payload. This token can be used to access protected endpoints by passing it in the Authorization header when making a request to the API. The token is long-lived in the sense that it's valid for 12 hours at least.

## Adding a hashPassword field to the User Model

To store the hashed password, we need to add a new field called `hashPassword` to the User model in the Prisma schema. This field will store the hashed password.

```prisma title="schema.prisma" linenums="13" hl_lines="4"
model User {
  id           String    @id @default(uuid())
  email        String    @unique
  hashPassword String
  Account      Account[]
}
```

To update the database schema, run the commands as follows:

```bash
bunx prisma db push
bunx prisma generate
```

## Add registration functionality

To implement the registration functionality, we need to create a new endpoint that allows users to register by providing an email and password. The server will hash the password and store the email and hashed password in the database.

### Register endpoint

The register endpoint is a POST request that accepts an email and password in the request body. The server will hash the password and store the email and hashed password in the database.

```http
POST http://localhost:3000/register
```

#### Request Body

```json
{
    "email": "test@gmail.com",
    "password": "123456"
}
```

#### Response

```json
{
    "message": "User created successfully"
}
```

### Implementing the register endpoint

To implement the register endpoint, we need to create a new route in the `src/index.ts` file.

```typescript title="src/index.ts" linenums="23" hl_lines="1-26"
app.post("/register", async (c) => {
  try {
    const body = await c.req.json();

    const bcryptHash = await Bun.password.hash(body.password, {
      algorithm: "bcrypt",
      cost: 4, // number between 4-31
    });

    const user = await prisma.user.create({
      data: {
        email: body.email,
        hashedPassword: bcryptHash,
        Account: {
          create: {
            balance: 0,
          },
        },
      },
    });

    return c.json({ message: `${user.email} created successfully}` });
  } catch (error) {
    return c.json({ error: error });
  }
});
```

1. The route listens for POST requests to the `/register` endpoint.
2. The request body is parsed to extract the email and password.
3. The password is hashed using the `Bun.password.hash` method.
4. The user is created in the database with the email and hashed password.
5. The `Account` model is created with a default balance of 0.
6. A success message is returned if the user is created successfully.
7. If an error occurs during the registration process, the server returns a JSON response with the error message.

#### Handling exceptions and errors from Prisma ORM

In the code snippet above, we use a try-catch block to handle exceptions and errors that may occur during the registration process. If an error occurs, the server will return a JSON response with the error message.

However, we need to know the exact error that occurred. To do this, we can use the `PrismaClientKnownRequestError` class to check if the error is a known Prisma error. If it is, we can return a more user-friendly error message.

```typescript title="src/index.ts" hl_lines="3"

import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";

```

```typescript title="src/index.ts" linenums="23" hl_lines="23-35"
app.post("/register", async (c) => {
  try {
    const body = await c.req.json();

    const bcryptHash = await Bun.password.hash(body.password, {
      algorithm: "bcrypt",
      cost: 4, // number between 4-31
    });

    const user = await prisma.user.create({
      data: {
        email: body.email,
        hashedPassword: bcryptHash,
        Account: {
          create: {
            balance: 0,
          },
        },
      },
    });

    return c.json({ message: `${user.email} created successfully}` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError) {
      // The .code property can be accessed in a type-safe manner
      if (e.code === 'P2002') {
        console.log(
          'There is a unique constraint violation, a new user cannot be created with this email'
        )
        return c.json({ message: 'Email already exists' })
      }
    }
    throw e
  }
});
```

## Add login functionaliy

To implement the login functionality, we need to create a new endpoint that allows users to authenticate by providing an email and password. The server will verify the email and password against the stored hash. If the credentials are correct, the server will issue a long-lived JWT token that the user can use to access authenticated API endpoints.

### Login endpoint

The login endpoint is a POST request that accepts an email and password in the request body. The server will verify the email and password against the stored hash. If the credentials are correct, the server will issue a long-lived JWT token that the user can use to access authenticated API endpoints.

```http
POST http://localhost:3000/login
```

#### Request Body

```json
{
    "email": "test@gmail.com",
    "password": "123456"
}
```

#### Response
    
```json
{
    "message": "Login successful",
    "token": "JWT_TOKEN_LIVES_HERE"
}
```

### Implementing the login endpoint

To implement the login endpoint, we need to create a new route in the `src/index.ts` file.

```typescript title="src/index.ts" linenums="58" hl_lines="1-25"
app.post("/login", async (c) => {
  try {
    const body = await c.req.json();

    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return c.json({ message: "User not found" });
    }

    const match = await Bun.password.verify(body.password, user.hashedPassword,"bcrypt");

    if (match) {
      return c.json({ message: "Login successful" });
    } else {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

  } catch (error) {
    throw new HTTPException(401, { message: 'Invalid credentials' })
  }
});
```

1. The route listens for POST requests to the `/login` endpoint.
2. The request body is parsed to extract the email and password.
3. The user is fetched from the database using the email.
4. If the user is not found, the server returns a JSON response with the message "User not found".
5. The password is verified against the stored hash using the `Bun.password.verify` method.
6. If the password matches the stored hash, the server returns a JSON response with the message "Login successful".
7. If the password does not match the stored hash, the server throws an HTTPException with a status code of 401 and a message "Invalid credentials".

To do this we need to import the `HTTPException` class from Hono.


```typescript title="src/index.ts" hl_lines="4"
import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";

```

8. If an error occurs during the login process, the server returns a JSON response with the message "Login failed".

#### Handling the JWT token in the login response

In the code snippet above, we verify the password against the stored hash. If the password matches the stored hash, the server returns a JSON response with the message "Login successful".

However, we need to issue a long-lived JWT token that the user can use to access authenticated API endpoints. 

To do this, we can use the JWT Authentication Helper from Hono. The helper provides methods to create and verify JWT tokens. 

To use this helper, you can import it as follows:

```typescript title="src/index.ts" hl_lines="5"
import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { decode, sign, verify } from 'hono/jwt'

```

Next, we can create a JWT token with the user's unique id as the payload and sign it with a secret key. The token can be sent back to the user in the login response.


```typescript title="src/index.ts" linenums="58" hl_lines="20-27"
app.post("/login", async (c) => {
  try {
    const body = await c.req.json();

    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return c.json({ message: "User not found" });
    }

    const match = await Bun.password.verify(
      body.password,
      user.hashedPassword,
      "bcrypt"
    );

    if (match) {
      const payload = {
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
      };
      const secret = "mySecretKey";
      const token = await sign(payload, secret);
      return c.json({ message: "Login successful", token: token });
    } else {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }
  } catch (error) {
    throw new HTTPException(401, { message: 'Invalid credentials' })
  }
});
```

!!! warning
    
    The secret key used to sign the JWT token should be kept secure and not exposed in the code. In a production environment, you should store the secret key in an environment variable or a secure location.

## Implementing authorization on protected endpoints

To implement authorization, we need to create a middleware that verifies the JWT token sent by the user in the Authorization header. If the token is valid, the user is authenticated and can access the protected endpoints.

### Middleware for verifying JWT tokens

To create a middleware for verifying JWT tokens, we need to create a new function that checks the Authorization header for the JWT token. If the token is valid, the user is authenticated and can access the protected endpoints.

Thankfully, Hono provides a middleware function called `jwt` that verifies the JWT token and decodes the payload. The middleware function can be used to protect the endpoints that require authentication.

The JWT Auth Middleware provides authentication by verifying the token with JWT. Authorization header value or cookie value specified by the cookie option will be used as a token.

To use the JWT Auth Middleware, you can import it as follows:

```typescript title="src/index.ts" hl_lines="6-7"
import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { decode, sign, verify } from "hono/jwt";
import { jwt } from 'hono/jwt'
import type { JwtVariables } from 'hono/jwt'
```

Specify the variable types to infer the `c.get('jwtPayload')` type.

```typescript title="src/index.ts" hl_lines="9-11"
import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { decode, sign, verify } from "hono/jwt";
import { jwt } from 'hono/jwt'
import type { JwtVariables } from 'hono/jwt'

type Variables = JwtVariables

const app = new Hono<{ Variables: Variables }>()
```

Next, we can create a middleware function called `auth` that verifies the JWT token sent by the user in the Authorization header.

```typescript title="src/index.ts" linenums="17" hl_lines="1-6"
app.use(
  "/protected/*",
  jwt({
    secret: 'mySecretKey',
  })
);
```

!!! warning
    
    The secret key used to sign the JWT token should be kept secure and not exposed in the code. In a production environment, you should store the secret key in an environment variable or a secure location.

The middleware function `jwt` verifies the JWT token sent by the user in the Authorization header. If the token is valid, the user is authenticated and can access the protected endpoints.

### Protected endpoint

The protected endpoint is a GET request that retrieves the user's account balance. The server will verify the JWT token sent by the user in the Authorization header. If the token is valid, the user is authenticated and can access the protected endpoint.

```http
GET http://localhost:3000/protected/account/balance
```

#### Request Headers

```http
Authorization
Bearer JWT
```

#### Response

```json
{
    "data": {
        "Account": [
            {
                "balance": 0,
                "id": "75a34064-f8c4-4a7e-90dd-4958c452fbf4"
            }
        ]
    }
}
```

### Implementing the protected endpoint

To implement the protected endpoint, we need to create a new route in the `src/index.ts` file.

```typescript title="src/index.ts" linenums="17" hl_lines="8-19"
app.use(
  "/protected/*",
  jwt({
    secret: 'mySecretKey',
  })
);

app.get("/protected/account/balance", async (c) => {
  const payload = c.get('jwtPayload')
  if (!payload) {
    throw new HTTPException(401, { message: "Unauthorized" });
  }
  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    select: { Account: { select: { balance: true, id: true } } },
  });

  return c.json({ data: user });
});
```

1. The middleware function `jwt` verifies the JWT token sent by the user in the Authorization header.
2. The protected endpoint listens for GET requests to the `/protected/account/balance` endpoint.
3. The middleware function `jwt` decodes the JWT token and stores the payload in the context.
4. If the JWT token is not valid, the server throws an HTTPException with a status code of 401 and a message "Unauthorized".
5. The user is fetched from the database using the user id from the JWT token.
6. The user's account balance is returned in the JSON response.


## Next steps

In the next tutorial, we will explore how to implement sending an email verification token to the user upon registration. The user will need to verify their email address before they can log in and access the protected endpoints.

Addtionally, we will be exploring on refresh tokens and how to implement them in the authentication flow as well as functionality of forgetting and resetting passwords.
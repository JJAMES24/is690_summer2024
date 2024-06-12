# Answer These Questions Here, you can add additional pages to answer questions, just link to them so that I can view these questions and see your answer or the link(s) to your answer.

## FastAPI and Pydantic

1. **What role does Pydantic play in FastAPI, and how does it enhance data validation and settings management?**
   - Provide examples from the project where Pydantic is used.
   
   Answer:  Pydantic models are used to define and validate the structure of request and response data. This ensures that the data conforms to expected formats and types, reducing errors and enhancing reliability.
   
   Examples : class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: UserRole

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huZG9lQGV4YW1wbGUuY29tIiwicm9sZSI6IkFVVEhFTlRJQ0FURUQiLCJleHAiOjE2MjQzMzQ5ODR9.ZGNjNjI2ZjI4MmYzNTk0MjVjNDk0ZjI4MjdjNGEzNmI1",
                "token_type": "bearer"
            }
        }


2. **Outline the complete process of handling a user login request in your FastAPI application. Provide a step-by-step explanation with code examples from the project.**

Answer: 
Step 1: Define the Login Route
The login route is defined in the FastAPI application using the @router.post decorator. This route handles the login request and returns a token if the login is successful.
@router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
):
    try:
        user = await UserService.login_user(session, form_data.username, form_data.password)
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name), "user_id": str(user.id)},
            expires_delta=access_token_expires
        )
        # Immediately decode to verify
        try:
            decoded = jwt.decode(access_token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            logging.info(f"Immediate decode check: {decoded}")
        except jwt.PyJWTError as e:
            logging.error(f"Immediate decode failed: {e}")
        
        return {"access_token": access_token, "token_type": "bearer"}
    except InvalidCredentialsException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

Step 2: Dependency Injection
The login function uses dependency injection to obtain the required form_data and session. The OAuth2PasswordRequestForm is a built-in form used for OAuth2 password flow, and get_db is a dependency that provides a database session.

form_data: OAuth2PasswordRequestForm = Depends()
session: AsyncSession = Depends(get_db)

Step 3: User Authentication
The UserService.login_user method is called to authenticate the user. This method checks the provided username and password against the database.

user = await UserService.login_user(session, form_data.username, form_data.password)

Step 4: Token Creation
Upon successful authentication, a JWT access token is created using the create_access_token function. The token includes user details such as email, role, and user ID, and it has an expiration time defined by the settings.

access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
access_token = create_access_token(
    data={"sub": user.email, "role": str(user.role.name), "user_id": str(user.id)},
    expires_delta=access_token_expires
)


Step 5: Token Verification
The access token is immediately decoded to verify its integrity. Any issues with the token are logged.

try:
    decoded = jwt.decode(access_token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    logging.info(f"Immediate decode check: {decoded}")
except jwt.PyJWTError as e:
    logging.error(f"Immediate decode failed: {e}")

Step 6: Return Response
Finally, the access token is returned in the response along with its type.

return {"access_token": access_token, "token_type": "bearer"}


3. **Explain the service repository pattern and how it is applied in your project. Provide an example of how routes are managed and linked to services.**

Answer : The service repository pattern is a design pattern that separates the data access logic into repository classes and the business logic into service classes. This pattern promotes a clean separation of concerns and enhances the maintainability and testability of the code.

Example: User Routes: These routes handle user-related endpoints.
In this example:

The UserService is instantiated within the route handler functions.
The service methods create_user and get_user_by_id are called to perform the respective operations.
The session is injected using FastAPI's Depends mechanism to manage the database session context.

## Database Management with Alembic and SQLAlchemy

4. **How does Alembic manage database migrations, and why is this important for maintaining database schemas?**
   - Illustrate with an example of a migration script from the project.

   Answer: Alembic is a lightweight database migration tool for usage with SQLAlchemy, used to handle database schema changes in a systematic and version-controlled manner. It is essential for maintaining database schemas because it allows for the consistent application of schema changes across different environments (development, testing, production) and ensures that the database schema evolves along with the application code.

   Example: 
   """initial migration

Revision ID: 6b62f34b7189
Revises: 
Create Date: 2024-04-26 20:38:55.377746

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '6b62f34b7189'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table('users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('nickname', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=100), nullable=True),
        sa.Column('last_name', sa.String(length=100), nullable=True),
        sa.Column('bio', sa.String(length=500), nullable=True),
        sa.Column('profile_picture_url', sa.String(length=255), nullable=True),
        sa.Column('linkedin_profile_url', sa.String(length=255), nullable=True),
        sa.Column('github_profile_url', sa.String(length=255), nullable=True),
        sa.Column('role', sa.Enum('ANONYMOUS', 'AUTHENTICATED', 'MANAGER', 'ADMIN', name='UserRole'), nullable=False),
        sa.Column('is_professional', sa.Boolean(), nullable=True),
        sa.Column('professional_status_updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
        sa.Column('is_locked', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('verification_token', sa.String(), nullable=True),
        sa.Column('email_verified', sa.Boolean(), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_nickname'), 'users', ['nickname'], unique=True)

def downgrade() -> None:
    op.drop_table('users')



## Pytest

5. **Why is Pytest critical for the development of the API?**
Answer : Pytest is critical for API development due to its simplicity, powerful features, detailed reporting, and integration capabilities. It helps ensure that APIs are robust, reliable, and maintainable by enabling comprehensive and automated testing. Using Pytest, developers can catch bugs early, validate functionality, and maintain high code quality, ultimately leading to better software and more reliable APIs.

## JWT and User Authentication

6. **Explain the functioning of JWT (JSON Web Tokens) in user authentication. How are JWTs generated, encoded, and used within the project?**
   - [Read this article and link to the code in the user management.](https://supertokens.com/blog/what-is-jwt)
   - Include a code snippet showing how JWTs are implemented in the project.

   Answer : JSON Web Tokens (JWT) play a critical role in user authentication in your FastAPI application. JWTs are used to securely transmit information between parties as a JSON object. This information is verified and trusted because it is digitally signed. JWTs can be signed using a secret (with HMAC algorithm) or a public/private key pair using RSA or ECDSA.

   Example: 
 @router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_db)):
    try:
        user = await UserService.login_user(session, form_data.username, form_data.password)
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name), "user_id": str(user.id)},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except InvalidCredentialsException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return payload


7. **Decode the following JWT and explain its contents:**
   - Token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsInJvbGUiOiJBRE1JTiIsInVzZXJfaWQiOiJjZGY4M2QzZi0zNzQ5LTRjZGQtOTRlYS1hNTVjZmMwNDhkMGYiLCJleHAiOjE3MTc2MTY4MjAuMjIwNzA5fQ.ANS8PgUiwPCmOvnZLYTCy_5WzLyhCDOx8aF4xu-Kaz8`
   - Use [jwt.io](https://jwt.io/) to decode and explain the contents.


   Answer: 
   Using jwt.io, the JWT token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsInJvbGUiOiJBRE1JTiIsInVzZXJfaWQiOiJjZGY4M2QzZi0zNzQ5LTRjZGQtOTRlYS1hNTVjZmMwNDhkMGYiLCJleHAiOjE3MTc2MTY4MjAuMjIwNzA5fQ.ANS8PgUiwPCmOvnZLYTCy_5WzLyhCDOx8aF4xu-Kaz8, when decoded, reveals the following information:
1. Header
      {
  "alg": "HS256",
  "typ": "JWT"
}
alg: "HS256" indicates that the token is signed using the HMAC SHA-256 algorithm.
typ: "JWT" indicates that the token type is JSON Web Token

2. Payload

   {
  "sub": "john.doe@example.com",
  "role": "ADMIN",
  "user_id": "cdf83d3f-3749-4cdd-94ea-a55cfc048d0f",
  "exp": 1717616820.220709
}

sub: Subject of the token, typically the user’s email or identifier. Here, it is "john.doe@example.com".
role: The role assigned to the user. Here, it is "ADMIN".
user_id: Unique identifier for the user. Here, it is "cdf83d3f-3749-4cdd-94ea-a55cfc048d0f".
exp: Expiration time of the token as a Unix timestamp. This means the token is valid until 1717616820.220709.



8. **Describe the user registration logic in your project. Provide a pseudo-code workflow from the registration request to storing the user in the database.**

Answer: In the provided FastAPI project, the user registration logic follows a structured workflow to ensure users are correctly registered and their information is securely stored in the database. Below is a step-by-step explanation of the process, illustrated with pseudo-code based on the actual code :

1. Receiving the Registration Request
2. Validating User Data
3. User Service Registration Method
4. Checking for Existing Email
5. Hashing the Password
6. Generating a Unique Nickname
7. Setting User Role and Initial Attributes
8. Saving the User to the Database
9. Sending a Verification Email
10. Returning the User Response

9. **Detail the steps involved in the user email verification process. Provide a pseudo-code workflow from sending a verification email to activating the user's account.**

Answer: 
1. User Registration
2. Sending Verification Email
3. Verification Link
4. Token Verification

## Security Practices

10. **How do you ensure the security of user passwords in your project? Discuss the hashing algorithm used and any additional security measures implemented.**
Answer: In the project, the security of user passwords is ensured through the use of robust hashing algorithms and additional security measures. The primary goals are to prevent unauthorized access and protect user data.
The project uses bcrypt for hashing passwords. Bcrypt is a password hashing function designed to be computationally intensive, making it resistant to brute-force attacks. The primary features of bcrypt that enhance security include:

Salt Generation: Bcrypt generates a unique salt for each password. This means that even if two users have the same password, their hashes will be different due to the unique salts.
Key Stretching: Bcrypt applies the hashing function multiple times (configurable through a work factor), making it significantly more time-consuming for attackers to perform brute-force attacks.

11. **Explain the difference between hashing and encoding. Provide examples from your project where each is used:**
Answer: Hashing and encoding serve different purposes in data processing and security.
1. Hashing is a one-way process that converts input data into a fixed-size string of characters, which is typically a hash code. It is used primarily for data integrity and security.
2. Encoding is a reversible process that converts data into another format using a scheme that is publicly available. It is used primarily for data transmission and storage.
    - **Hashing:** Example and explanation with code
    Answer: Hashing is used to securely store passwords. In the project, hashing is implemented using the bcrypt algorithm to ensure that passwords are not stored in plaintext and are resistant to brute-force attacks.
    Example: 
    from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

    
 - **Encoding:** Example and explanation with code
 Answer:Encoding is used for converting data into a different format for transmission or storage. For instance, Base64 encoding is often used to encode binary data (like images or files) into a text format.

 Example:
 async def upload_profile_picture(file: UploadFile) -> str:
    content = await file.read()
    encoded_content = encode_to_base64(content)
    return encoded_content


## Project Management with Docker and CI/CD

12. **Discuss the advantages of using Docker Compose for running your project. How does it help in maintaining a consistent development and deployment environment?**
Answer: Docker Compose is a powerful tool that simplifies the process of managing multi-container Docker applications. It allows you to define and run multi-container Docker applications using a YAML file, making it easy to set up and manage your project’s environment. Here are some key advantages of using Docker Compose for your project:

1. Simplifies Configuration Management
      Single Configuration File: Docker Compose uses a docker-compose.yml file to configure your application’s services. This single file contains all the configurations for your services, making it easy to manage and maintain.
2. onsistent Development Environment
      Reproducibility: Docker Compose ensures that everyone on your team is using the same environment, reducing the "it works on my machine" problem. This consistency is crucial for smooth development and debugging. 
3. Streamlined Deployment Process
      Scaling: It allows you to scale services up or down with a single command, making it easy to handle changes in load and requirements.

13. **Describe the role of GitHub Actions in your project's CI/CD pipeline. How do you automate testing and deployment using GitHub Actions?**

Answer: GitHub Actions is a powerful tool for automating workflows directly from your GitHub repository. It plays a critical role in the CI/CD (Continuous Integration and Continuous Deployment) pipeline by enabling automated testing, building, and deployment of your project. Here's how GitHub Actions are integrated into your project's CI/CD pipeline and how they automate testing and deployment.GitHub Actions workflows are defined in YAML files stored in the .github/workflows directory of your repository.

## API Design and Implementation

14. **What are REST APIs, and how do they function in your project? Provide an example of a REST endpoint from your user management system.**

Answer: REST (Representational State Transfer) APIs are a set of rules and conventions for building and interacting with web services. RESTful APIs follow a stateless, client-server architecture and are designed around resources, each identified by a URL. REST APIs use standard HTTP methods (GET, POST, PUT, DELETE) to perform operations on these resources.n the project, REST APIs are used to handle various operations related to user management, such as registration, login, profile updates, and more. Each operation is mapped to a specific endpoint and handled using appropriate HTTP methods.

Example:
from fastapi import APIRouter, Body, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .models import UserCreate, UserResponse
from .services import UserService
from .dependencies import get_db, get_email_service

router = APIRouter()

@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
async def register(
    user_data: UserCreate = Body(...),
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service)):
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    return user



15. **What is HATEOAS (Hypermedia as the Engine of Application State)? Provide an example of its implementation in your project's API responses, along with a screenshot.**

Answer: HATEOAS is a constraint of the REST application architecture that distinguishes it from other network application architectures. With HATEOAS, a client interacts with a network application entirely through hypermedia provided dynamically by application servers. This means that the client doesn't need to have prior knowledge of how to interact with the application beyond a basic understanding of hypermedia.
![alt text](image-1.png)
![alt text](image-2.png)


## Role-Based Access Control (RBAC)

16. **What is Role-Based Access Control (RBAC) and how is it implemented in your project?**
Answer:Role-Based Access Control (RBAC) is a method of regulating access to resources based on the roles assigned to individual users within an organization. Roles are defined according to job functions, and permissions to perform certain operations are assigned to specific roles rather than to individual users. Users are then assigned to roles, thereby inheriting the permissions of those roles.The implementation of RBAC within the project involves defining user roles, assigning permissions to these roles, and enforcing these permissions throughout the application.



17. **Explain the different user roles defined in your project (ANONYMOUS, AUTHENTICATED, MANAGER, ADMIN) and their permissions.**
Answer:
1. ANONYMOUS: Can read publicly available data.
2. AUTHENTICATED: Can read and update their own data.
3. MANAGER: Can read and update their own data, read team data, update team data, and manage team resources.
4. ADMIN: Has full access to all actions within the system, including managing all users and resources.

18. **Provide a code example showing how RBAC is enforced in one of your FastAPI endpoints.**

Answer: Checking if the current user has the necessary role to perform the action.

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from .models import User

def get_current_user(session: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    user = UserService.get_user_by_token(session, token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return user

def require_role(required_role: UserRole):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        return current_user
    return role_checker

## Route Parameters and Pydantic Schemas

19. **Explain how route parameters are used in FastAPI. Provide an example of a route that takes a parameter and demonstrate how it is used within the endpoint.**

Answer: Route parameters in FastAPI allow you to capture parts of the URL path and use them within your endpoint. This is useful for creating dynamic routes where parts of the URL can vary. Route parameters are specified using curly braces {} in the path declaration.

Example: 
Retrieving user details based on the user ID.
1. Client Request:
      A client sends a GET request to /users/123.
2. Parameter Extraction:
      FastAPI extracts the user_id from the URL, converts it to an integer, and passes it to the get_user function.
3. Database Query:
      The session.get(User, user_id) call retrieves the user with ID 123 from the database.
4. Response:
      If the user is found, their data is returned as a response. If not, a 404 Not Found error is returned.


20. **How does FastAPI use Pydantic schemas to generate Swagger documentation? Provide an example from your project where a Pydantic schema is used and show the corresponding Swagger documentation.**
Answer: FastAPI uses Pydantic models to define request and response schemas. These models automatically generate documentation in the Swagger UI, providing a clear and interactive API reference.

Exmaple: 

Pydantic Schema Defintion :
rom pydantic import BaseModel, EmailStr

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_active: bool

    class Config:
        orm_mode = True

Endpoint:
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from .models import User
from .dependencies import get_db

router = APIRouter()

@router.get("/users/{user_id}", response_model=UserResponse, tags=["Users"])
async def get_user(user_id: int, session: AsyncSession = Depends(get_db)):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

Swagger Documentation:
![alt text](image.png)




These questions ensure a comprehensive assessment of the students' understanding of the topics related to your project setup, focusing on practical implementations and theoretical concepts.
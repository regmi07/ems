using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;

namespace ServerLibrary.Repositories.Implementation {
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext): IUserAccount {
        public async Task<GeneralResponse> CreateAsync(Register user){
            if(user is null) return new GeneralResponse(false,"Model is empty!");
            var checkUser = await FindUserByEmail(user.Email!);
            if (checkUser != null) return new GeneralResponse(false,"User with given email has already registered!");
            // save user to database
            var applicationUser = await AddToDatabase(new ApplicationUser(){
                FullName = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // check, create and assign role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
            // first user to register in this application is assigned a role of Admin.
            if(checkAdminRole is null) {
                var createAdminRole = await AddToDatabase(new SystemRole {Name=Constants.Admin});
                await AddToDatabase(new UserRole(){RoleId=createAdminRole.Id,UserId=applicationUser.Id});
                return new GeneralResponse(true,"Account created Successfully!");
            }

            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
            SystemRole response = new();
            if(checkUserRole is null) {
                response = await AddToDatabase(new SystemRole {Name=Constants.User});
                await AddToDatabase(new UserRole(){RoleId=response.Id,UserId=applicationUser.Id});
            }else{
                await AddToDatabase(new UserRole(){RoleId=checkUserRole.Id,UserId=applicationUser.Id});
            }

            return new GeneralResponse(true,"Account created successfully!");

        }

        public async Task<LoginResponse> SignInAsync(Login user){
            if(user is null) return new LoginResponse(false,"Model is empty!");
            var applicationUser = await FindUserByEmail(user.Email!);
            if(applicationUser is null) return new LoginResponse(false,"User not found!");

            // compare and verify password
            if(!BCrypt.Net.BCrypt.Verify(user.Password,applicationUser.Password))
                return new LoginResponse(false,"Invalid Email or Password!");
            // check if user has been assigned a role
            var getUserRoles = await FindUserRole(applicationUser.Id);
            if(getUserRoles is null) return new LoginResponse(false,"user hasn't been assigned a role!");
            // get the role name
            var getRoleName = await FindRoleName(getUserRoles.RoleId);
            if(getRoleName is null) return new LoginResponse(false,"Invalid role!");

            string jwtToken = GenerateToken(applicationUser,getRoleName.Name!);
            string refreshToken = GenerateRefreshToken();
            // save the refresh token to the database
            var findUserRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
            if(findUserRefreshToken is not null){
                findUserRefreshToken.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }else {
                await AddToDatabase(new RefreshTokenInfo(){Token=refreshToken,UserId=applicationUser.Id});
            }
            return new LoginResponse(true,"Login successful!",jwtToken,refreshToken);

        }

        private async Task<UserRole> FindUserRole(int UserId) => await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == UserId);
        private async Task<SystemRole> FindRoleName(int RoleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == RoleId);

        private string GenerateToken(ApplicationUser user,string role) {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
            var userClaims = new[]{
                new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                new Claim(ClaimTypes.Name,user.FullName!),
                new Claim(ClaimTypes.Email,user.Email!),
                new Claim(ClaimTypes.Role,role)
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience:config.Value.Audience,
                claims:userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials:credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        private string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<ApplicationUser> FindUserByEmail(string email) =>
            await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));

        public async Task<T> AddToDatabase<T>(T model){
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken refreshToken){
            if(refreshToken is null) return new LoginResponse(false,"Model is empty!");
            // get refresh token
            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(refreshToken.Token!));
            if(findToken is null) return new LoginResponse(false,"Refresh token is required");
            // get user with the current refresh token
            var findUser = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
            if(findUser is null) return new LoginResponse(false,"Refresh token could not be generated because user not found!");

            var userRole = await FindUserRole(findUser.Id);
            var roleName = await FindRoleName(userRole.RoleId);
            string jwtToken = GenerateToken(findUser,roleName.Name!);
            string newRefreshToken = GenerateRefreshToken();

            var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == findUser.Id);
            if(updateRefreshToken is null) return new LoginResponse(false,"Refresh token could not be generated because user has not signed in!");

            updateRefreshToken.Token = newRefreshToken;
            await appDbContext.SaveChangesAsync();
            return new LoginResponse(true, "Token generated successfully!",jwtToken,newRefreshToken);
            
        }
    
    }
}
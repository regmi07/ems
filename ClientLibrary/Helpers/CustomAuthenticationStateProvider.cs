using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;

namespace ClientLibrary.Helpers{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService): AuthenticationStateProvider{
        private readonly ClaimsPrincipal annonymous = new (new ClaimsIdentity());
        public override async Task<AuthenticationState> GetAuthenticationStateAsync(){
            var stringToken = await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken)) return await Task.FromResult(new AuthenticationState(annonymous));

            var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
            if(deserializeToken == null) return await Task.FromResult(new AuthenticationState(annonymous));

            var getUSerClaims = DecryptToken(deserializeToken.Token!);
            if(getUSerClaims == null) return await Task.FromResult(new AuthenticationState(annonymous));

            var claimsPrincipal = SetClaimPrinciple(getUSerClaims);
            return await Task.FromResult(new AuthenticationState(claimsPrincipal));
        }

        public async Task UpdateAuthenticationState(UserSession userSession){
            var claimsPrincipal = new ClaimsPrincipal();
            if(userSession.Token != null || userSession.RefreshToken != null){
                var serializeSession = Serializations.SerializeObj(userSession);
                await localStorageService.SetToken(serializeSession);
                var getUserClaims = DecryptToken(userSession.Token!);
                claimsPrincipal = SetClaimPrinciple(getUserClaims);
            }else{
                await localStorageService.RemoveToken();
            }
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        private static CustomUserClaims DecryptToken(string jwtToken){
            if(string.IsNullOrEmpty(jwtToken)) return new CustomUserClaims();

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);
            var userId = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
            var name = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Name);
            var email = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Email);
            var role = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Role);
            return new CustomUserClaims(userId!.Value, name!.Value, email!.Value,role!.Value);
        }

        private static ClaimsPrincipal SetClaimPrinciple(CustomUserClaims userClaims){
            if(userClaims.Email is null) return new ClaimsPrincipal();
            return new ClaimsPrincipal(new ClaimsIdentity(
                new List<Claim>{
                    new(ClaimTypes.NameIdentifier, userClaims.Id!),
                    new(ClaimTypes.Name, userClaims.Name!),
                    new(ClaimTypes.Email, userClaims.Email!),
                    new(ClaimTypes.Role, userClaims.Role!),
                },"JwtAuth"));
        }
    }
}
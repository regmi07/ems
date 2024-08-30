using System.Net;
using BaseLibrary.DTOs;
using ClientLibrary.Services.Contract;
namespace ClientLibrary.Helpers {
    public class CusotmHttpHandler(GetHttpClient getHttpClient, LocalStorageService localStorageService, IUserAccountService accountService): DelegatingHandler {
       protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken){
            bool isLoginUrl = request.RequestUri!.AbsoluteUri.Contains("login");
            bool isRegisterUrl = request.RequestUri!.AbsoluteUri.Contains("register");
            bool isRefreshTokenUrl = request.RequestUri!.AbsoluteUri.Contains("refresh_token");

            if(isLoginUrl || isRegisterUrl || isRefreshTokenUrl){
                return await base.SendAsync(request,cancellationToken);

            }

            var result = await base.SendAsync(request,cancellationToken);
            if(result.StatusCode == HttpStatusCode.Unauthorized){
                // get token from local storage
                var stringToken = await localStorageService.GetToken();
                if (stringToken == null) return result;
                // check if headers contains token
                string token = string.Empty;
                try{
                    token = request.Headers.Authorization!.Parameter!;
                }catch{}

                var deserializedToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
                if(deserializedToken is null) return result;
                if(string.IsNullOrEmpty(token)){
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deserializedToken.Token);
                    return await base.SendAsync(request,cancellationToken);
                }

                // generate refresh token
                var newJwtToken = await GetRefreshToken(deserializedToken.RefreshToken!);
                if(string.IsNullOrEmpty(newJwtToken)) return result;

            }
            return result;
       }
        private async Task<string> GetRefreshToken(string refreshToken){
            var result = await accountService.RefreshTokenInfo(new RefreshToken{Token=refreshToken});
            string serializedToken = Serializations.SerializeObj(new UserSession(){
                Token = result.Token,
                RefreshToken = result.RefreshToken
            });
            await localStorageService.SetToken(serializedToken);
            return result.Token;
        }
    }
}
using System.Net.Http.Json;
using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Contract;

namespace ClientLibrary.Services.Implentation{
    public class UserAccountService(GetHttpClient getHttpClient): IUserAccountService{
        public const string AuthUrl = "api/authentication";
        public async Task<GeneralResponse> CreateAsync(Register user){
            var httpClient = getHttpClient.GetPublicHttpClient();
            var response = await httpClient.PostAsJsonAsync($"{AuthUrl}/register",user);
            if(!response.IsSuccessStatusCode) return new GeneralResponse(false,"Error occured");
            return await response.Content.ReadFromJsonAsync<GeneralResponse>();
        }

        public async Task<LoginResponse> SignInAsync(Login user){
            var httpClient = getHttpClient.GetPublicHttpClient();
            var response = await httpClient.PostAsJsonAsync($"{AuthUrl}/login",user);
            if(!response.IsSuccessStatusCode) return new LoginResponse(false,"Error occured");
            return await response.Content.ReadFromJsonAsync<LoginResponse>();
        }

        public Task<LoginResponse> RefreshTokenInfo(RefreshToken token){
            throw new NotImplementedException();
        }

        public async Task<WeatherForecast[]> GetWeatherForecasts(){
            var httpClient = await getHttpClient.GetPrivateHttpClient();
            var response = await httpClient.GetFromJsonAsync<WeatherForecast[]>("api/weatherforecast");
            return response;
        }

    }
}
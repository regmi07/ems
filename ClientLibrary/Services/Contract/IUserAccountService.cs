
using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ClientLibrary.Services.Contract{
    public interface IUserAccountService{
        Task<GeneralResponse> CreateAsync(Register user);
        Task<LoginResponse> SignInAsync(Login user);
        Task<LoginResponse> RefreshTokenInfo(RefreshToken token);
        Task<WeatherForecast[]> GetWeatherForecasts();
    }
}
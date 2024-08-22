using Blazored.LocalStorage;

namespace ClientLibrary.Helpers{
    public class LocalStorageService(ILocalStorageService localStorageService){
        private const string LocalStorageKey = "authentication-token";
        public async Task<string> GetToken() => await localStorageService.GetItemAsStringAsync(LocalStorageKey);
        public async Task SetToken(string item) => await localStorageService.SetItemAsStringAsync(LocalStorageKey, item);
        public async Task RemoveToken() => await localStorageService.RemoveItemAsync(LocalStorageKey);
    }
}
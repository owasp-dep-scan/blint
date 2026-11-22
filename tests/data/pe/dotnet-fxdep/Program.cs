using Newtonsoft.Json;

var app = WebApplication.CreateBuilder(args).Build();
app.MapPost("/import", (string body) => JsonConvert.DeserializeObject<Dictionary<string, string>>(body));
app.Run();

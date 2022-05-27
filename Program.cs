using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer; // JwtBearerDefaults
using Microsoft.AspNetCore.Identity; // IdentityUser, IdentityRole
using Microsoft.EntityFrameworkCore; // UseSqlite()
using Microsoft.IdentityModel.Tokens; // TokenValidationParameters
using SecureApi.Data;

var builder = WebApplication.CreateBuilder(args);



// Add services to the container.

// Lägg till context till DI och konfigurera den till att använda sqlite.
builder.Services.AddDbContext<ApplicationContext>(options => {
    options.UseSqlite(builder.Configuration.GetConnectionString("sqlite"));
});

// Sätt upp Identity-hantering och ange vilket context som ska användas för att lagra användare, roller, claims.
// Man kan också sätta regler för tex lösenord och utlåsningsprinciper.
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>(options => { // AddIdentity<IdentityUser, IdentityRole> är boiler plate, men options är frivilligt.
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true; // False tillåter flera konton med samma email, men det är inte så normalt.
        options.Lockout.MaxFailedAccessAttempts = 5; // Om man misslyckas med att logga in så här många gånger...
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(20); // ...måste man vänta så här länge innan man får försöka igen.
    })
    .AddEntityFrameworkStores<ApplicationContext>(); // Boiler plate. Tala om för EF och Identity-systemet vilken context som ska spara användare och roller.

// Lägg till authentication till DI och konfigurera.
builder.Services
    .AddAuthentication(options => {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters() {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey( 
                Encoding.ASCII.GetBytes(builder.Configuration.GetValue<string>("apikey"))
            ),
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuer = false,
            ClockSkew = TimeSpan.Zero
        };
    });

// Lägg till authorization till DI och sätt upp policies.
builder.Services.AddAuthorization(options => {
    options.AddPolicy("Plebs", policy => policy.RequireClaim("Pleb")); // Skapar en policy som motvarar en roll. Kan sedan kontrolleras med [Authorize(policy: "Plebs")] i controllern.
    options.AddPolicy("Admins", policy => policy.RequireClaim("Admin"));
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();



// Configure the HTTP request pipeline.

// Pipeline med middleware nedan.
// Pipeline definierar ordningen och vilka middleware som körs på alla requests och responses.
if (app.Environment.IsDevelopment()) // Standard.
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection(); // Standard.
app.UseAuthentication(); // Tillagd för att akrivera autentisering. Måste ligga efter UseHttpsRedirection och före UseAuthorization
app.UseAuthorization(); // Standard.

app.MapControllers(); // Standard. Skapar endpoints baserat på [Route("path1")], [HttpGet("path2")], etc.



app.Run();

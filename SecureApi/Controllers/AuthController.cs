using System.IdentityModel.Tokens.Jwt; // JwtSecurityToken, JwtSecurityTokenHandler
using System.Security.Claims; // Claim, ClaimTypes
using System.Text; // Encoding
using Microsoft.AspNetCore.Identity; // UserManager, SignInManager, RoleManager, IdentityUser, IdentityRole
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens; // SigningCredentials, SymmetricSecurityKey, SecurityAlgorithms
using SecureApi.ViewModels;

namespace SecureApi.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _rolemanager;
        public AuthController(IConfiguration config, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> rolemanager)
        {
            _config = config;
            _userManager = userManager;
            _signInManager = signInManager;
            _rolemanager = rolemanager;
        }


        [HttpGet("SeedRoles")]
        public async Task<IActionResult> SeedRoles()
        {
            if (!await _rolemanager.RoleExistsAsync("Pleb"))
            {
                await _rolemanager.CreateAsync(new IdentityRole("Pleb"));
            }
            if (!await _rolemanager.RoleExistsAsync("Admin"))
            {
                await _rolemanager.CreateAsync(new IdentityRole("Admin"));
            }
            
            return Ok();
        }


        [HttpPost("register")]
        public async Task<ActionResult<UserViewModel>> RegisterUser(RegisterViewModel model)
        {
            // Skapa ny IdentityUser och fyll på med data från modellen.
            var user = new IdentityUser() {
                Email = model.Email!.ToLower(),
                UserName = model.Email!.ToLower()
            };

            // Spara användaren till databasen.
            var result = await _userManager.CreateAsync(user, model.Password);

            // Kontrollera att det gick bra.
            if (result.Succeeded)
            {
                // Tilldela claims till användaren
                await _userManager.AddClaimAsync(user, new Claim("User", "")); // Skapa en ny (egen) claim på denna användare. Bara key behövs, den struntar i value.
                await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Name, user.UserName));
                await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Email, user.Email));
                await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.NameIdentifier, user.Id));
                if (model.IsPleb)
                {
                    await _userManager.AddClaimAsync(user, new Claim("Pleb", ""));
                    await _userManager.AddToRoleAsync(user, "Pleb");
                }
                if (model.IsAdmin)
                {
                    await _userManager.AddClaimAsync(user, new Claim("Admin", ""));
                    await _userManager.AddToRoleAsync(user, "Admin");
                }

                // Skapa modell för att skicka tillbaka.
                var userModel = new UserViewModel() {
                    UserName = user.UserName,
                    Token = await CreateJwtTokenAsync(user)
                };
                return StatusCode(201, userModel); // Created
            }
            else
            {
                // Skicka med felinfo om det gick dåligt.
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError("User registration", error.Description);
                }
                return StatusCode(500, ModelState); // Internal server error
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserViewModel>> Login(LoginViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName); // Hämta användare ur databasen.
            if (user == null)
                return Unauthorized("Felaktigt användarnamn"); // 401
            
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false); // Försök logga in. Hur det gick sparas i variabeln.

            if (!result.Succeeded)
                return Unauthorized("Du är för dålig för att logga in."); // 401
            
            var userModel = new UserViewModel() { // Skapa modell för att skicka tillbaka.
                UserName = model.UserName,
                Token = await CreateJwtTokenAsync(user)
            };

            return Ok(userModel);
        }



        private async Task<string> CreateJwtTokenAsync(IdentityUser user)
        {
            // Kommer att hämtas ifrån AppSettings...
            var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("apikey")); // Hämta från appsettings.development.json

            // Skapa en lista av Claims som kommer innehålla
            // information som är av värde för behörighetskontroll...
            // var claims = new List<Claim> // Denna lista används inte längre, men är ett bra exempel. userClaims används istället.
            // {
            //     new Claim(ClaimTypes.Name, user.UserName),
            //     new Claim(ClaimTypes.Email, user.Email),
            //     new Claim("MyCustomClaimKey", "MyCustomClaimValue"), // Hur man gör en egen claim.
            //     new Claim("Admin", "") // Policy kollar efter clam med namnet, men struntar i värdet.
            // };

            var userClaims = (await _userManager.GetClaimsAsync(user)).ToList();
            var roles = (await _userManager.GetRolesAsync(user));
            userClaims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role))); // Lägg in rollerna som claims.

            // Skapa ett nytt token...
            var jwt = new JwtSecurityToken(
                claims: userClaims,
                // notBefore: Från när skall biljetten/token vara giltig.
                // Vi kan sätta detta till en datum i framtiden om biljetten/token
                // skall skapas men inte vara giltig på en gång...
                notBefore: DateTime.Now,
                // Sätt giltighetstiden på biljetten i detta fallet en vecka.
                expires: DateTime.Now.AddDays(7), // Tiden för giltigheten bör läggas någon annanstans, inte hårdkodas.
                // Skapa en instans av SigningCredential klassen
                // som används för att skapa en hash och signering av biljetten.
                signingCredentials: new SigningCredentials(
                // Vi använder en SymmetricSecurityKey som tar vår hemlighet
                // som argument och sedan talar vi om vilken algoritm som skall
                // användas för att skapa hash värdet.
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512Signature
                )
            );

        // Vi använder klassen JwtSecurityTokenHandler och dess metod WriteToken för att
        // skapa en sträng av vårt token...
        return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}
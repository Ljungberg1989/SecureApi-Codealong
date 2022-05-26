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
        

        
        // GET: api/auth/seedroles
        [HttpGet("SeedRoles")]
        public async Task<IActionResult> SeedRoles()
        {
            var roles = new List<string>() {"Pleb", "Admin"};
            foreach (var role in roles)
            {
                if (!await _rolemanager.RoleExistsAsync(role))
                    await _rolemanager.CreateAsync(new IdentityRole(role));
            }
            
            return Ok();
        }
        
        
        
        // POST: api/auth/register
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


        
        // POST: api/auth/login
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
            var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("apikey")); // Hämta nyckeln från appsettings.development.json och gör den till en byte-array.

            var userClaims = (await _userManager.GetClaimsAsync(user)).ToList(); // Hämta denna användares claims ur databasen. ToList för att kunna göra AddRange senare.
            var roles = (await _userManager.GetRolesAsync(user)); // Hämta denna användares roller ur databasen. (Strängar.)
            var claimsToAdd = roles.Select(role => new Claim(ClaimTypes.Role, role)); // Projicera rollerna som claims. (Gör en lista med claims baserat på listan med roller.)
            userClaims.AddRange(claimsToAdd); // Lägg till claims som representerar roller.
            
            // TODO: Lite kommentarer kvar.
            var token = new JwtSecurityToken( // Skapa en ny token (biljett).
                claims: userClaims, // Ange de claims som skapades ovan.
                notBefore: DateTime.Now, // Starttid som biljetten är giltig. Vanligtvis direkt, men man kan sätta en tid i framtiden vid behov.
                expires: DateTime.Now.AddDays(7), // Sluttid då biljetten slutar gälla. Värdet bör inte hårdkodas, utan hämtas från någon annan stans.
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

        string tokenString = new JwtSecurityTokenHandler().WriteToken(token); // Skapa strängen som representerar vårt jwt-token. Denna sträng skickas sedan med i alla anrop.
        return tokenString;
        }
    }
}
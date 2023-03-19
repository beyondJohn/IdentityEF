// usings are defined in GlobalUsings.cs
namespace IdentityEF.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public ValuesController(ApplicationDbContext context, UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _context = context;
            _userManager = userManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                try
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

                    var token = new JwtSecurityToken(
                        issuer: _configuration["Jwt:Issuer"],
                        audience: _configuration["Jwt:Issuer"],
                        expires: DateTime.Now.AddDays(1),
                        claims: authClaims,
                        signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                        );

                    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                }
                catch (Exception ex)
                {
                    return UnprocessableEntity(new { message = ex.Message });
                }
            }

            return Unauthorized(new {message = "User not found."});
        }

        [HttpPost("addUser")]
        public async Task<IActionResult> AddUser(LoginModel loginModel)
        {
            var user = new IdentityUser { Email = loginModel.Email, UserName = loginModel.Email };

            var result = await _userManager.CreateAsync(user);

            if (result.Succeeded) return Ok(result);

            return UnprocessableEntity(new { message = "Failed: User not created" });
        }

        [HttpPost("addPw")]
        public async Task<IActionResult> AddPassword(LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            var result = await _userManager.AddPasswordAsync(user, loginModel.Password);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    success = result.Succeeded,
                    message = "Password set successfully!"
                });
            }
            else
            {
                return UnprocessableEntity(new
                {
                    message = "Failed: Password was not added."
                });
            }
        }

        [HttpPost("updatePw")]
        public async Task<IActionResult> UpdatePassword(LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                // // reset password for user
                // get reset token for user
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                // check to see if the password update field exists
                if (loginModel.PasswordUpdate != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, token, loginModel.PasswordUpdate);

                    if (result.Succeeded) return Ok(new
                    {
                        success = result.Succeeded,
                        message = "Password reset successfully!"
                    });
                }
                else
                {
                    return UnprocessableEntity(new { message = "Failed: Password not reset." });
                }
            }

            return Unauthorized(new {message = "User not found."});
        }
    }
}

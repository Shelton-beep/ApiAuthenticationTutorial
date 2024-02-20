using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiAuthenticationTutorial.Services.AuthService
{
    public class AuthService : IAuthService
    {
        private readonly DataContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(DataContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<ServiceResponse<string>> Login(string email, string password)
        {
            var response = new ServiceResponse<string>();

            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == email.ToLower());
            if (user == null)
            {
                response.IsSuccess = false;
                response.Message = "User not found";
                return response;
            }

            if (!VerifyPasswordHash(password, user.PasswordHash))
            {
                response.IsSuccess = false;
                response.Message = "Incorrect password";
                return response;
            }

            response.Data = CreateToken(user);
            return response;
        }

        public async Task<ServiceResponse<int>> Register(User user, string password)
        {
            if (await UserExists(user.Email))
            {
                return new ServiceResponse<int>
                {
                    IsSuccess = false,
                    Message = "User already exists"
                };
            }

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new ServiceResponse<int>
            {
                IsSuccess = true,
                Data = user.Id,
                Message = "Created new user"
            };
        }

        public async Task<bool> UserExists(string email)
        {
            return await _context.Users.AnyAsync(user => user.Email.ToLower() == email.ToLower());
        }

        private bool VerifyPasswordHash(string password, string passwordHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        private string GetIssuer()
        {
            return _configuration["Jwt:Issuer"];
        }

        private string GetAudience()
        {
            return _configuration["Jwt:Audience"];
        }

        private SymmetricSecurityKey GetSecretKey()
        {
            var secret = _configuration["Jwt:Secret"];
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            return new SymmetricSecurityKey(secretBytes);
        }

        private string CreateToken(User user)
        {
            var signingCredentials = new SigningCredentials(GetSecretKey(), SecurityAlgorithms.HmacSha256Signature);

            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Email)
    };

            var expires = DateTime.UtcNow.AddHours(1);

            var token = new JwtSecurityToken(
                issuer: GetIssuer(),
                audience: GetAudience(),
                expires: expires,
                signingCredentials: signingCredentials,
                claims: claims
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }



        public async Task<ServiceResponse<bool>> ChangePassword(int userId, string newPassword)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return new ServiceResponse<bool>
                {
                    IsSuccess = false,
                    Message = "User not found"
                };
            }

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword, BCrypt.Net.BCrypt.GenerateSalt(12));

            await _context.SaveChangesAsync();

            return new ServiceResponse<bool>
            {
                Data = true,
                Message = "Password has been changed"
            };
        }
    }
}

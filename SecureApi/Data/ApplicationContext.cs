using Microsoft.AspNetCore.Identity.EntityFrameworkCore; // IdentityDbContext
using Microsoft.EntityFrameworkCore;

namespace SecureApi.Data
{
    public class ApplicationContext : IdentityDbContext // IdentityDbContext ärver DbContext så all vanlig funktionalitet följer med, plus den för inloggning och rollhantering.
    {
        public ApplicationContext(DbContextOptions options) 
            : base(options)
        {
        }
    }
}
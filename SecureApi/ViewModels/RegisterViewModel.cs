using System.ComponentModel.DataAnnotations;

namespace SecureApi.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [EmailAddress(ErrorMessage = "Ur mail is craap.")]
        public string? Email { get; set; }

        [Required]
        public string? Password { get; set; }

        public bool IsPleb { get; set; } = false;
        public bool IsAdmin { get; set; } = false;
    }
}
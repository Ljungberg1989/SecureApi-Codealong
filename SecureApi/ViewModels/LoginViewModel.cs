using System.ComponentModel.DataAnnotations;

namespace SecureApi.ViewModels
{
  public class LoginViewModel
  {
    [Required]
    public string? UserName { get; set; }

    [Required]
    public string? Password { get; set; }
  }
}
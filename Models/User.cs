using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LoginAndRegistration.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        
        [Display(Name="First Name")]
        [Required(ErrorMessage = "Enter your first name")]
        [MinLength(2, ErrorMessage = "First name must be at least 2 characters")]
        public string FirstName { get; set; }

        [Display(Name="Last Name")]
        [Required(ErrorMessage = "Enter your last name")]
        [MinLength(2, ErrorMessage = "Last name must be at least 2 characters")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Enter your email")]
        [EmailAddress(ErrorMessage ="Enter a valid email address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Enter a password")]
        [MinLength(8, ErrorMessage = "Must be at least 8 characters")]
        public string Password { get; set; }

        [NotMapped]
        [Display(Name="Confirm Password")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string Password2 { get; set; }

        public DateTime CreatedAt {get;set;} = DateTime.Now;
        public DateTime UpdatedAt {get;set;} = DateTime.Now;
    }

    public class LoginUser
    {
        // No other fields!
        public string Email {get; set;}
        public string Password { get; set; }
    }
}
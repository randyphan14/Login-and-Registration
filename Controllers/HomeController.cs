using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoginAndRegistration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;


namespace LoginAndRegistration.Controllers
{
    public class HomeController : Controller
    {
        private MyContext dbContext;
        
        // here we can "inject" our context service into the constructor
        public HomeController(MyContext context)
        {
            dbContext = context;
        }

        [HttpGet]
        [Route("")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [Route("login")]
        public IActionResult Login()
        {
            return View();
        }

        [HttpGet]
        [Route("success")]
        public IActionResult Success()
        {
            string LocalVariable = HttpContext.Session.GetString("Active");
            if (LocalVariable != "true") {
                return RedirectToAction("Index");
            }
            return View();
        }

        [Route("create")]
        [HttpPost]
        public IActionResult Create(User yourSurvey)
        {
            // Handle your form submission here
            if(ModelState.IsValid)
            {
                if(dbContext.Users.Any(u => u.Email == yourSurvey.Email))
                {
                    // Manually add a ModelState error to the Email field, with provided
                    // error message
                    ModelState.AddModelError("Email", "Email already in use!");
                    
                    // You may consider returning to the View at this point
                    return View("Index");
                }
                // do somethng!  maybe insert into db?  then we will redirect
                PasswordHasher<User> Hasher = new PasswordHasher<User>();
                yourSurvey.Password = Hasher.HashPassword(yourSurvey, yourSurvey.Password);
                dbContext.Add(yourSurvey);
                dbContext.SaveChanges();
                // Console.WriteLine("Success");
                HttpContext.Session.SetString("Active", "true");
                return RedirectToAction("Success");
            }
            else
            {
                // Oh no!  We need to return a ViewResponse to preserve the ModelState, and the errors it now contains!
                Console.WriteLine("FAIL");
                return View("Index");
            }
        }
        [Route("trylogin")]
        [HttpPost]
        public IActionResult TryLogin(LoginUser userSubmission)
        {
            if(ModelState.IsValid)
            {
                // If inital ModelState is valid, query for a user with provided email
                var userInDb = dbContext.Users.FirstOrDefault(u => u.Email == userSubmission.Email);
                // If no user exists with provided email
                if(userInDb == null)
                {
                    // Add an error to ModelState and return to View!
                    ModelState.AddModelError("Email", "Invalid Email/Password");
                    return View("Login");
                }
                
                // Initialize hasher object
                var hasher = new PasswordHasher<LoginUser>();
                
                // verify provided password against hash stored in db
                var result = hasher.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.Password);
                
                // result can be compared to 0 for failure
                if(result == 0)
                {
                    // handle failure (this should be similar to how "existing email" is handled)
                    ModelState.AddModelError("Email", "Invalid Email/Password");
                    return View("Login");
                }
                HttpContext.Session.SetString("Active", "true");
                return RedirectToAction("Success");
            }
            return View("Login");
        }

        [Route("logout")]
        [HttpGet]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }     
    }
}

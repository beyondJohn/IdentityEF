﻿namespace IdentityEF.Models
{
    public class LoginModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string? PasswordUpdate { get; set; }
    }
}

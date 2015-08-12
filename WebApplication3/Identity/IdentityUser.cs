using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;

namespace WebApplication3.Identity
{
    public class IdentityUser : IUser
    {
        public IdentityUser()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        public IdentityUser(string userName)
            : this()
        {
            this.UserName = userName;
        }

        /// <summary>
        /// User ID
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// User's name
        /// </summary>
        public string UserName { get; set; }

        // Used to record failures for the purposes of lockout
        /// <summary>
        /// 
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        // Navigation property for user claims
        //public virtual ICollection<TClaim> Claims { get; }

        // Email
        public virtual string Email { get; set; }

        // True if the email is confirmed, default is false
        public virtual bool EmailConfirmed { get; set; }

        // Is lockout enabled for this user
        public virtual bool LockoutEnabled { get; set; }

        // DateTime in UTC when lockout ends, any 
        // time in the past is considered not locked out.
        public virtual DateTime? LockoutEndDateUtc { get; set; }

        // Navigation property for user logins
        //public virtual ICollection<TLogin> Logins { get; }

        // The salted/hashed form of the user password
        public virtual string PasswordHash { get; set; }

        // PhoneNumber for the user
        public virtual string PhoneNumber { get; set; }

        // True if the phone number is confirmed, default is false
        public virtual bool PhoneNumberConfirmed { get; set; }

        // Navigation property for user roles
        public virtual ICollection<IdentityRole> Roles { get; set; }

        // A random value that should change whenever a users 
        // credentials have changed (password changed, login removed)
        public virtual string SecurityStamp { get; set; }

        // Is two factor enabled for the user
        public virtual bool TwoFactorEnabled { get; set; }
    }
}
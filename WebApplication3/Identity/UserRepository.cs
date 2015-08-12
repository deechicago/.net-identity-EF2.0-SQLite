using System;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace WebApplication3.Identity
{
    internal class UserRepository<TUser>
        where TUser : IdentityUser
    {
        private readonly IdentityEntities _identityEntities;

        /// <summary>
        /// Constructor that takes a IdentityEntities instance 
        /// </summary>
        public UserRepository(IdentityEntities identityEntities)
        {
            _identityEntities = identityEntities;
        }

        /// <summary>
        /// Returns all users in Users table
        /// </summary>
        /// <returns></returns>
        internal IQueryable<TUser> GetUsers()
        {
            // var res = _identityEntities.Users.Select(user=>CreateUserAsync(user));
            return _identityEntities.Users.Select(user =>
                new IdentitySample.Models.ApplicationUser
                {
                    Id = user.Id,
                    Roles = user.Roles.Select(role => new IdentitySample.Models.ApplicationRole { Id = role.Id, Name = role.Name }).ToList<IdentityRole>(),
                    //user.RoleId = foundUser.RoleId;
                    UserName = user.UserName,
                    Email = String.IsNullOrEmpty(user.Email) ? null : user.Email,
                    EmailConfirmed = user.EmailConfirmed == 1,
                    PasswordHash = String.IsNullOrEmpty(user.PasswordHash) ? null : user.PasswordHash,
                    SecurityStamp = String.IsNullOrEmpty(user.SecurityStamp) ? null : user.SecurityStamp,
                    PhoneNumber = String.IsNullOrEmpty(user.PhoneNumber) ? null : user.PhoneNumber,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed == 1,
                    TwoFactorEnabled = user.TwoFactorEnabled == 1,
                    LockoutEnabled = user.LockoutEnabled == 1,
                    LockoutEndDateUtc = user.LockoutEndDateUtc.HasValue
                        ? user.LockoutEndDateUtc.Value
                        : DateTime.Now,
                    AccessFailedCount = user.AccessFailedCount
                }) as IQueryable<TUser>;
            //return _identityEntities.Users.Select(user => CreateUserAsync(user)) as IQueryable<TUser>;
        }

        internal async Task AddNewUserAsync(IdentityUser user)
        {
            if (user != null)
            {
                _identityEntities.Users.Add(new Users
                {
                    Id = user.Id,
                    //RoleId = user.RoleId,
                    UserName = user.UserName,
                    PasswordHash = user.PasswordHash,
                    SecurityStamp = user.SecurityStamp,
                    Email = user.Email,
                    EmailConfirmed = Convert.ToInt32(user.EmailConfirmed),
                    PhoneNumber = user.PhoneNumber,
                    PhoneNumberConfirmed = Convert.ToInt32(user.PhoneNumberConfirmed),
                    AccessFailedCount = user.AccessFailedCount,
                    LockoutEnabled = Convert.ToInt32(user.LockoutEnabled),
                    LockoutEndDateUtc = user.LockoutEndDateUtc,
                    TwoFactorEnabled = Convert.ToInt32(user.TwoFactorEnabled)
                });

                await _identityEntities.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Updates a user in the Users table
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task UpdateUserAsync(TUser user)
        {
            if (user != null)
            {
                Users currentUser = _identityEntities.Users.SingleOrDefault(u => u.Id == user.Id);

                if (currentUser != null)
                {
                    currentUser.UserName = user.UserName;
                    currentUser.PasswordHash = user.PasswordHash;
                    currentUser.SecurityStamp = user.SecurityStamp;
                    currentUser.Email = user.Email;
                    currentUser.EmailConfirmed = Convert.ToInt32(user.EmailConfirmed);
                    currentUser.PhoneNumber = user.PhoneNumber;
                    currentUser.PhoneNumberConfirmed = Convert.ToInt32(user.PhoneNumberConfirmed);
                    currentUser.LockoutEnabled = Convert.ToInt32(user.LockoutEnabled);
                    currentUser.LockoutEndDateUtc = user.LockoutEndDateUtc;
                    currentUser.AccessFailedCount = user.AccessFailedCount;
                    currentUser.TwoFactorEnabled = Convert.ToInt32(user.TwoFactorEnabled);

                    await _identityEntities.SaveChangesAsync();
                }
            }
        }

        internal async Task<TUser> GetUserByIdAsync(string userId)
        {
            if (!String.IsNullOrEmpty(userId))
            {
                Users foundUser = _identityEntities.Users.SingleOrDefault(u => u.Id == userId);
                if (foundUser != null)
                {
                    return await CreateUserAsync(foundUser);
                }
            }
            return await Task.FromResult<TUser>(null);
        }

        internal async Task<TUser> GetUserByNameAsync(string userName)
        {
            if (!String.IsNullOrEmpty(userName))
            {
                Users foundUser = _identityEntities.Users.SingleOrDefault(u => u.UserName == userName);
                if (foundUser != null)
                {
                    return await CreateUserAsync(foundUser);
                }
            }
            return await Task.FromResult<TUser>(null);
        }

        public Task<string> GetPasswordHashAsync(string userId)
        {
            if (!String.IsNullOrEmpty(userId))
            {
                Users foundUser = _identityEntities.Users.SingleOrDefault(u => u.Id == userId);
                if (foundUser != null)
                {
                    return Task.FromResult(foundUser.PasswordHash);
                }
            }
            return Task.FromResult(String.Empty);
        }

        /// <summary>
        /// Returns user's role name
        /// </summary>
        /// <param name="userId">The user's id</param>
        /// <returns></returns>
        public Task<List<string>> FindUserRolesByUserIdAsync(string userId)
        {
            Users currentUser = _identityEntities.Users.SingleOrDefault(user => user.Id == userId);

            if (currentUser != null && currentUser.Roles != null)
            {
                //if (!String.IsNullOrEmpty(currentUser.Roles.Name))
                {
                    return Task.FromResult(currentUser.Roles.Select(role => role.Name).ToList());
                }
            }
            //return String.Empty;
            return null;
        }

        /// <summary>
        /// Returns TUser instance using an email of user
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public async Task<TUser> GetUserByEmailAsync(string email)
        {
            if (!String.IsNullOrEmpty(email))
            {
                Users foundUser = _identityEntities.Users.SingleOrDefault(u => u.Email == email);
                if (foundUser != null)
                {
                    return await CreateUserAsync(foundUser);
                }
            }
            //return new IdentityUser();
            return await Task.FromResult<TUser>(null);
        }

        /// <summary>
        /// Deletes a user from the Users table
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task DeleteUserAsync(TUser user)
        {
            if (user != null)
            {
                await DeleteUserAsync(user.Id);
            }
        }

        private Task<TUser> CreateUserAsync(Users foundUser)
        {
            TUser user = (TUser)Activator.CreateInstance(typeof(TUser));
            user.Id = foundUser.Id;
            user.Roles = foundUser.Roles.Select(role => new IdentitySample.Models.ApplicationRole { Id = role.Id, Name = role.Name }).ToList<IdentityRole>();
            //user.RoleId = foundUser.RoleId;
            user.UserName = foundUser.UserName;
            user.Email = String.IsNullOrEmpty(foundUser.Email) ? null : foundUser.Email;
            user.EmailConfirmed = foundUser.EmailConfirmed == 1;
            user.PasswordHash = String.IsNullOrEmpty(foundUser.PasswordHash) ? null : foundUser.PasswordHash;
            user.SecurityStamp = String.IsNullOrEmpty(foundUser.SecurityStamp) ? null : foundUser.SecurityStamp;
            user.PhoneNumber = String.IsNullOrEmpty(foundUser.PhoneNumber) ? null : foundUser.PhoneNumber;
            user.PhoneNumberConfirmed = foundUser.PhoneNumberConfirmed == 1;
            user.TwoFactorEnabled = foundUser.TwoFactorEnabled == 1;
            user.LockoutEnabled = foundUser.LockoutEnabled == 1;
            user.LockoutEndDateUtc = foundUser.LockoutEndDateUtc.HasValue
                        ? foundUser.LockoutEndDateUtc.Value
                        : DateTime.Now;
            user.AccessFailedCount = foundUser.AccessFailedCount;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Deletes a user from the Users table
        /// </summary>
        /// <param name="userId">The user's id</param>
        /// <returns></returns>
        private async Task DeleteUserAsync(string userId)
        {
            if (!String.IsNullOrEmpty(userId))
            {
                Users foundUser = _identityEntities.Users.SingleOrDefault(u => u.Id == userId);
                if (foundUser != null)
                {
                    _identityEntities.Users.Remove(foundUser);
                    await _identityEntities.SaveChangesAsync();
                }
            }
        }
    }
}
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using System.Security.Claims;

namespace WebApplication3.Identity
{
    public class UserStore<TUser> : IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserEmailStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser, string>,
        IUserLockoutStore<TUser, string>,
        IUserStore<TUser>
        where TUser : IdentityUser
    {
        private IdentityEntities _identityEntities;
        private UserRepository<TUser> _userRepository;
        private RoleRepository _roleRepository;
        private UserRolesRepository _userRolesRepository;
        private UserClaimsRepository _userClaimsRepository;
        private UserLoginsRepository _userLoginsRepository;

        /// <summary>
        /// Constructor that takes an IdentityEntities instance
        /// </summary>
        public UserStore(IdentityEntities identityEntities)
        {
            _identityEntities = identityEntities;
            _userRepository = new UserRepository<TUser>(_identityEntities);
            _roleRepository = new RoleRepository(_identityEntities);
            _userRolesRepository = new UserRolesRepository(_identityEntities);
            _userClaimsRepository = new UserClaimsRepository(_identityEntities);
            _userLoginsRepository = new UserLoginsRepository(_identityEntities);
        }

        public async Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            await _userRepository.AddNewUserAsync(user);
        }

        public async Task DeleteAsync(TUser user)
        {
            if (user != null)
            {
                await _userRepository.DeleteUserAsync(user);
            }
        }

        public async Task<TUser> FindByIdAsync(string userId)
        {
            if (String.IsNullOrEmpty(userId))
            {
                throw new ArgumentException("Null or empty argument: userId");
            }

            return await _userRepository.GetUserByIdAsync(userId);
        }

        public async Task<TUser> FindByNameAsync(string userName)
        {
            if (String.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Null or empty argument: userName");
            }

            return await _userRepository.GetUserByNameAsync(userName);
        }

        public async Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            await _userRepository.UpdateUserAsync(user);
        }

        public void Dispose()
        {
            if (_identityEntities != null)
            {
                _identityEntities.Dispose();
                _identityEntities = null;
            }
        }

        public async Task AddToRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (String.IsNullOrEmpty(roleName))
            {
                throw new ArgumentException("Argument cannot be null or empty: roleName.");
            }

            string roleId = await _roleRepository.GetRoleIdAsync(roleName);
            if (!String.IsNullOrEmpty(roleId))
            {
                await _userRolesRepository.SetUserRoleAsync(user.Id, roleId);
            }
        }

        public Task<IList<string>> GetRolesAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return _userRolesRepository.FindUserRolesByUserIdAsync(user.Id);
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException("roleName");
            }

            var currentUserRole = await _userRolesRepository.FindUserRolesByUserIdAsync(user.Id);
            foreach (var r in currentUserRole)
            {
                if (StringComparer.Ordinal.Compare(r, roleName) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException("role");
            }
            await _userRolesRepository.RemoveUserRoleAsync(user.Id, roleName);
        }

        public async Task AddClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("user");
            }

            await _userClaimsRepository.AddNewClaimsAsync(claim, user.Id);
        }

        public async Task<IList<System.Security.Claims.Claim>> GetClaimsAsync(TUser user)
        {
            if (user != null)
            {
                ClaimsIdentity identity = await _userClaimsRepository.FindByUserIdAsync(user.Id);

                return await Task.FromResult(identity.Claims.ToList());
            }
            return await Task.FromResult<List<Claim>>(null);
        }

        public async Task RemoveClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            await _userClaimsRepository.DeleteClaimAsync(user, claim);
        }

        public async Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return await _userRepository.GetPasswordHashAsync(user.Id);
        }

        public async Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return !String.IsNullOrEmpty(await _userRepository.GetPasswordHashAsync(user.Id));
        }

        public async Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrEmpty(passwordHash))
            {
                throw new ArgumentNullException("passwordHash");
            }
            await Task.Run(() => user.PasswordHash = passwordHash);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.SecurityStamp);
        }

        public async Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrEmpty(stamp))
            {
                throw new ArgumentNullException("stamp");
            }
            await Task.Run(() => user.SecurityStamp = stamp);
        }

        public IQueryable<TUser> Users
        {
            get { return _userRepository.GetUsers(); }
        }

        public async Task<TUser> FindByEmailAsync(string email)
        {
            if (String.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException("email");
            }

            return await _userRepository.GetUserByEmailAsync(email);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.EmailConfirmed);
        }

        public async Task SetEmailAsync(TUser user, string email)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException("email");
            }
            user.Email = email;
            await _userRepository.UpdateUserAsync(user);
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.EmailConfirmed = confirmed;
            await _userRepository.UpdateUserAsync(user);
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrEmpty(phoneNumber))
            {
                throw new ArgumentNullException("phoneNumber");
            }
            user.PhoneNumber = phoneNumber;
            await _userRepository.UpdateUserAsync(user);
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumberConfirmed = confirmed;
            await _userRepository.UpdateUserAsync(user);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.TwoFactorEnabled = enabled;
            await _userRepository.UpdateUserAsync(user);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            //return Task.FromResult(user.LockoutEndDateUtc.HasValue
            //    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
            //    : new DateTimeOffset());
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.LockoutEndDateUtc.HasValue
                ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                : new DateTimeOffset());
        }

        public async Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount++;
            await _userRepository.UpdateUserAsync(user);
            return user.AccessFailedCount;
        }

        public async Task ResetAccessFailedCountAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount = 0;
            await _userRepository.UpdateUserAsync(user);
        }

        public async Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnabled = enabled;
            await _userRepository.UpdateUserAsync(user);
        }

        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEndDateUtc = lockoutEnd.UtcDateTime;
            await _userRepository.UpdateUserAsync(user);
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            await _userLoginsRepository.AddNewLoginAsync(user, login);
        }

        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var userId = await _userLoginsRepository.FindUserIdByLoginAsync(login);

            if (userId != null)
            {
                return await _userRepository.GetUserByIdAsync(userId);
            }

            return await Task.FromResult<TUser>(null);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return await _userLoginsRepository.FindAllByUserIdAsync(user.Id);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            await _userLoginsRepository.DeleteAsync(user, login);
        }
    }
}
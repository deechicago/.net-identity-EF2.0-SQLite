using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace WebApplication3.Identity
{
    public class UserRolesRepository
    {
        private IdentityEntities _identityEntities;

        /// <summary>
        /// Constructor that takes a MySQLDatabase instance 
        /// </summary>
        public UserRolesRepository(IdentityEntities identityEntities)
        {
            _identityEntities = identityEntities;
        }

        /// <summary>
        /// Returns user's role name
        /// </summary>
        /// <param name="userId">The user's id</param>
        /// <returns></returns>
        public Task<IList<string>> FindUserRolesByUserIdAsync(string userId)
        {
            Users currentUser = _identityEntities.Users.SingleOrDefault(user => user.Id == userId);

            if (currentUser != null && currentUser.Roles != null)
            {
                //if (!String.IsNullOrEmpty(currentUser.Roles.Name))
                {
                    return Task.FromResult<IList<string>>(currentUser.Roles.Select(role=>role.Name).ToList());
                }
            }
            //return String.Empty;
            return null;
        }

        /// <summary>
        /// Sets to user given role ID
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="roleId"></param>
        /// <returns></returns>
        public async Task SetUserRoleAsync(string userId, string roleId)
        {
            if (!String.IsNullOrEmpty(userId) && !String.IsNullOrEmpty(roleId))
            {
                Users currentUser = _identityEntities.Users.SingleOrDefault(user => user.Id == userId);
                if (currentUser != null)
                {
                    Roles currentRole = currentUser.Roles.SingleOrDefault(role => role.Id == roleId);
                    currentRole.Id = roleId;
                    await _identityEntities.SaveChangesAsync();
                }
            }
        }

        /// <summary>
        /// Sets roleId of a given user to null
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task RemoveUserRoleAsync(string userId, string roleName)
        {
            if (!String.IsNullOrEmpty(userId))
            {
                Users currentUser = _identityEntities.Users.SingleOrDefault(user => user.Id == userId);
                if (currentUser != null)
                {
                    Roles currentRole = currentUser.Roles.SingleOrDefault(role => role.Name == roleName);
                    currentUser.Id = null;
                    await _identityEntities.SaveChangesAsync();
                }
            }
        }
    }
}
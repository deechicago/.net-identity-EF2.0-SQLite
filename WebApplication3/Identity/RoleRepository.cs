using IdentitySample.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace WebApplication3.Identity
{
    public class RoleRepository
    {
        private IdentityEntities _identityEntities;

        /// <summary>
        /// Constructor that takes an IdentityEntities instance 
        /// </summary>
        public RoleRepository(IdentityEntities identityEntities)
        {
            _identityEntities = identityEntities;
        }

        /// <summary>
        /// Returns all roles in Roles table
        /// </summary>
        /// <typeparam name="TRole"></typeparam>
        /// <returns></returns>
        public IQueryable<TRole> GetAllRoles<TRole>() where TRole : IdentityRole
        {
            return _identityEntities.Roles.Select(role => new IdentitySample.Models.ApplicationRole { Name = role.Name, Id = role.Id }) as IQueryable<TRole>;
        }

        /// <summary>
        /// Deltes a role from the Roles table
        /// </summary>
        /// <param name="roleId">The role Id</param>
        /// <returns></returns>
        public async Task DeleteRoleAsync(string roleId)
        {
            if (!String.IsNullOrEmpty(roleId))
            {
                Roles currentRole = _identityEntities.Roles.SingleOrDefault(role => role.Id == roleId);

                if (currentRole != null)
                {
                    _identityEntities.Roles.Remove(currentRole);
                    await _identityEntities.SaveChangesAsync();
                }
            }
        }

        /// <summary>
        /// Adds a new Role in the Roles table
        /// </summary>
        /// <param name="role">The user's role</param>
        /// <returns></returns>
        public async Task AddNewRoleAsync(IdentityRole role)
        {
            if (role != null)
            {
                _identityEntities.Roles.Add(new Roles
                {
                    Id = role.Id,
                    Name = role.Name
                });
                await _identityEntities.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Returns a role name given the roleId
        /// </summary>
        /// <param name="roleId">The role Id</param>
        /// <returns>Role name</returns>
        public async Task<string> GetRoleNameAsync(string roleId)
        {
            if (!String.IsNullOrEmpty(roleId))
            {
                Roles currentRole = _identityEntities.Roles.SingleOrDefault(role => role.Id == roleId);
                if (currentRole != null)
                {
                    return await Task.FromResult(currentRole.Name);
                }
            }
            return String.Empty;
        }

        /// <summary>
        /// Returns the role Id using a role name
        /// </summary>
        /// <param name="roleName">Role's name</param>
        /// <returns>Role's Id</returns>
        public async Task<string> GetRoleIdAsync(string roleName)
        {
            if (!String.IsNullOrEmpty(roleName))
            {
                Roles currentRole = _identityEntities.Roles.SingleOrDefault(role => role.Name == roleName);
                if (currentRole != null)
                {
                    return await Task.FromResult(currentRole.Id);
                }
            }
            return String.Empty;
        }

        /// <summary>
        /// Gets the IdentityRole given the role Id
        /// </summary>
        /// <param name="roleId"></param>
        /// <returns></returns>
        public async Task<IdentityRole> GetRoleByIdAsync(string roleId)
        {
            if (!String.IsNullOrEmpty(roleId))
            {
                var currentRole = _identityEntities.Roles.SingleOrDefault(role => role.Id == roleId);
                if (currentRole != null)
                {
                    return await Task.FromResult(new ApplicationRole { Id = roleId, Name = currentRole.Name, Description = currentRole.Description });
                }
            }
            return null;
        }

        /// <summary>
        /// Gets the IdentityRole given the role name
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task<IdentityRole> GetRoleByNameAsync(string roleName)
        {
            if (!String.IsNullOrEmpty(roleName))
            {
                string roleId = await GetRoleIdAsync(roleName);
                if (!String.IsNullOrEmpty(roleId))
                {
                    return new IdentityRole(roleName, roleId);
                }
            }
            return null;
        }

        public async Task UpdateRoleAsync(IdentityRole role)
        {
            if (role != null)
            {
                Roles currentRole = _identityEntities.Roles.SingleOrDefault(userRole => userRole.Id == role.Id);
                if (currentRole != null)
                {
                    currentRole.Name = role.Name;
                    await _identityEntities.SaveChangesAsync();
                }
            }
        }
    }
}
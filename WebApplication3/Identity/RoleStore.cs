using Microsoft.AspNet.Identity;
using System;
using System.Linq;

namespace WebApplication3.Identity
{
    public class RoleStore<TRole> : IQueryableRoleStore<TRole>, IRoleStore<TRole>
        where TRole : IdentityRole
    {
        private RoleRepository _roleRepository;
        private IdentityEntities _identityEntities;

        /// <summary>
        /// Constructor that takes an IdentityEntities instance
        /// </summary>
        public RoleStore(IdentityEntities identityEntities)
        {
            _identityEntities = identityEntities;
            _roleRepository = new RoleRepository(_identityEntities);
        }

        public IQueryable<TRole> Roles
        {
            get 
            {
                return _roleRepository.GetAllRoles<TRole>(); 
            }
        }

        public async System.Threading.Tasks.Task CreateAsync(TRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            await _roleRepository.AddNewRoleAsync(role);
        }

        public async System.Threading.Tasks.Task DeleteAsync(TRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            await _roleRepository.DeleteRoleAsync(role.Id);
        }

        public async System.Threading.Tasks.Task<TRole> FindByIdAsync(string roleId)
        {
            return await _roleRepository.GetRoleByIdAsync(roleId) as TRole;
        }

        public async System.Threading.Tasks.Task<TRole> FindByNameAsync(string roleName)
        {
            return await _roleRepository.GetRoleByNameAsync(roleName) as TRole;
        }

        public async System.Threading.Tasks.Task UpdateAsync(TRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            await _roleRepository.UpdateRoleAsync(role);
        }

        public void Dispose()
        {
            if (_identityEntities != null)
            {
                _identityEntities.Dispose();
                _identityEntities = null;
            }
        }
    }
}
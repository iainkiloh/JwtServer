﻿//------------------------------------------------------------------------------
// <auto-generated>This code was generated by LLBLGen Pro v5.4.</auto-generated>
//------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JwtSecurityContracts.Persistence
{
	/// <summary>Static class for (extension) methods for fetching and projecting instances of JwtSecurityContracts.DtoClasses.UserDto from the entity model.</summary>
	public static partial class UserDtoPersistence
	{
		private static readonly System.Linq.Expressions.Expression<Func<JwtSecurity.EntityClasses.UserEntity, JwtSecurityContracts.DtoClasses.UserDto>> _projectorExpression = CreateProjectionFunc();
		private static readonly Func<JwtSecurity.EntityClasses.UserEntity, JwtSecurityContracts.DtoClasses.UserDto> _compiledProjector = CreateProjectionFunc().Compile();
	
		/// <summary>Empty static ctor for triggering initialization of static members in a thread-safe manner</summary>
		static UserDtoPersistence() { }
	
		/// <summary>Extension method which produces a projection to JwtSecurityContracts.DtoClasses.UserDto which instances are projected from the 
		/// results of the specified baseQuery, which returns JwtSecurity.EntityClasses.UserEntity instances, the root entity of the derived element returned by this query.</summary>
		/// <param name="baseQuery">The base query to project the derived element instances from.</param>
		/// <returns>IQueryable to retrieve JwtSecurityContracts.DtoClasses.UserDto instances</returns>
		public static IQueryable<JwtSecurityContracts.DtoClasses.UserDto> ProjectToUserDto(this IQueryable<JwtSecurity.EntityClasses.UserEntity> baseQuery)
		{
			return baseQuery.Select(_projectorExpression);
		}
		
		/// <summary>Extension method which produces a projection to JwtSecurityContracts.DtoClasses.UserDto which instances are projected from the
		/// JwtSecurity.EntityClasses.UserEntity entity instance specified, the root entity of the derived element returned by this method.</summary>
		/// <param name="entity">The entity to project from.</param>
		/// <returns>JwtSecurity.EntityClasses.UserEntity instance created from the specified entity instance</returns>
		public static JwtSecurityContracts.DtoClasses.UserDto ProjectToUserDto(this JwtSecurity.EntityClasses.UserEntity entity)
		{
			return _compiledProjector(entity);
		}
		
		private static System.Linq.Expressions.Expression<Func<JwtSecurity.EntityClasses.UserEntity, JwtSecurityContracts.DtoClasses.UserDto>> CreateProjectionFunc()
		{
			return p__0 => new JwtSecurityContracts.DtoClasses.UserDto()
			{
				PasswordHash = p__0.PasswordHash,
				Salt = p__0.Salt,
				UserEmail = p__0.UserEmail,
				UserId = p__0.UserId,
				UserRoles = p__0.UserRoles.Select(p__1 => new JwtSecurityContracts.DtoClasses.UserDtoTypes.UserRole()
				{
					Role = new JwtSecurityContracts.DtoClasses.UserDtoTypes.UserRoleTypes.Role()
					{
						RoleId = p__1.Role.RoleId,
						RoleName = p__1.Role.RoleName,
					},
				}).ToList(),
	// __LLBLGENPRO_USER_CODE_REGION_START ProjectionRegion_UserDto 
	// __LLBLGENPRO_USER_CODE_REGION_END 
			};
		}
	}
}


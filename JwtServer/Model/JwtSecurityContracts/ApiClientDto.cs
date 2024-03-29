﻿//------------------------------------------------------------------------------
// <auto-generated>This code was generated by LLBLGen Pro v5.4.</auto-generated>
//------------------------------------------------------------------------------
using System;
using System.ComponentModel;
using System.Runtime.Serialization;
using System.Collections.Generic;

namespace JwtSecurityContracts.DtoClasses
{ 
	/// <summary> DTO class which is derived from the entity 'ApiClient'.</summary>
	[Serializable]
	[DataContract]
	public partial class ApiClientDto
	{
		/// <summary>Gets or sets the ClientId field. Derived from Entity Model Field 'ApiClient.ClientId'</summary>
		[DataMember]
		public System.String ClientId { get; set; }
		/// <summary>Gets or sets the ClientName field. Derived from Entity Model Field 'ApiClient.ClientName'</summary>
		[DataMember]
		public System.String ClientName { get; set; }
		/// <summary>Gets or sets the ClientSecret field. Derived from Entity Model Field 'ApiClient.ClientSecret'</summary>
		[DataMember]
		public System.String ClientSecret { get; set; }
		/// <summary>Gets or sets the RefreshTokenLifetimeMinutes field. Derived from Entity Model Field 'ApiClient.RefreshTokenLifetimeMinutes'</summary>
		[DataMember]
		public System.Int32 RefreshTokenLifetimeMinutes { get; set; }
		/// <summary>Gets or sets the TokenLifetimeMinutes field. Derived from Entity Model Field 'ApiClient.TokenLifetimeMinutes'</summary>
		[DataMember]
		public System.Int32 TokenLifetimeMinutes { get; set; }
	}

}





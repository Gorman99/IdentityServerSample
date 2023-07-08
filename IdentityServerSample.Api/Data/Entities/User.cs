using Microsoft.AspNetCore.Identity;

namespace IdentityServerSample.Api.Data.Entities;

public class User : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
}
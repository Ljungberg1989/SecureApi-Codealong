using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureApi.Controllers;

[ApiController]
[Route("api/TestRoles")]
public class TestRoles : ControllerBase
{
    [HttpGet("anyone")]
    public ActionResult Anyone()
    {
        return Ok();
    }

    [HttpGet("AnyoneSignedIn")]
    [Authorize]
    public ActionResult AnyoneSignedIn()
    {
        return Ok();
    }

    [HttpGet("Pleb")]
    [Authorize(Roles = "Pleb")]
    public ActionResult Pleb()
    {
        return Ok();
    }

    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public ActionResult Admin()
    {
        return Ok();
    }

    [HttpGet("PlebOrAdmin")]
    [Authorize(Roles = "Pleb, Admin")]
    public ActionResult PlebOrAdmin()
    {
        return Ok();
    }

    [HttpGet("PlebAndAdmin")]
    [Authorize(Roles = "Pleb")]
    [Authorize(Roles = "Admin")]
    public ActionResult PlebAndAdmin()
    {
        return Ok();
    }
}
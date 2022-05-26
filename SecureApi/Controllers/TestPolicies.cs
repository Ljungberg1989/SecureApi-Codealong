using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureApi.Controllers
{
    [ApiController]
    [Route("api/TestPolicies")]
    public class TestPolicies : ControllerBase
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
        [Authorize(policy: "Plebs")]
        public ActionResult Pleb()
        {
            return Ok();
        }

        [HttpGet("admin")]
        [Authorize(policy: "Admins")]
        public ActionResult Admin()
        {
            return Ok();
        }

        [HttpGet("PlebOrAdmin")]
        [Authorize(policy: "Plebs, Admins")] // BUG: Inte rätt sätt, kolla hur man gör.
        public ActionResult PlebOrAdmin()
        {
            return Ok();
        }

        [HttpGet("PlebAndAdmin")]
        [Authorize(policy: "Plebs")]
        [Authorize(policy: "Admins")]
        public ActionResult PlebAndAdmin()
        {
            return Ok();
        }
    }
}
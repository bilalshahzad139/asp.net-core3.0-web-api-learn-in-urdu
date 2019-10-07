using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using CoreApiTesting.Helper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;

namespace CoreApiTesting.Controllers
{
    [Route("api/main")]
    [ApiController]
    public class MainController : ControllerBase
    {
        IWebHostEnvironment _env;
        public MainController(IWebHostEnvironment env)
        {
            _env = env;
        }


        [HttpGet("gettoken")]
        public Object GetToken()
        {
            string key = "my_secret_key_12345";
            var issuer = "http://mysite.com";
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var permClaims = new List<Claim>();
            permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            permClaims.Add(new Claim("valid", "1"));
            permClaims.Add(new Claim("userid", "1"));
            permClaims.Add(new Claim("name", "bilal"));

            var token = new JwtSecurityToken(issuer,
                            issuer,
                            permClaims,
                            expires: DateTime.Now.AddDays(1),
                            signingCredentials: credentials);
            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);
            return new { data = jwt_token };


        }



        [HttpPost("getname1")]
        public ActionResult<String> GetName1()
        {
            if (User.Identity.IsAuthenticated)
            {
                var claims = User.Claims;
                return "Valid";
            }
            else
            {
                return "Invalid";
            }
        }

        [Authorize]
        [HttpPost("getname2")]
        public Object GetName2()
        {
            var claims = User.Claims;
            var name = claims.Where(p => p.Type == "name").FirstOrDefault()?.Value;
            return new
            {
                data = name
            };
        }


        [Authorize(Policy = "IsValid")]
        [HttpPost("getname3")]
        public Object GetName3()
        {
            var claims = User.Claims;
            var name = claims.Where(p => p.Type == "name").FirstOrDefault()?.Value;
            return new
            {
                data = name
            };
        }


        [ClaimDTOAttribute]
        [Authorize(Policy = "IsValid")]
        [HttpPost("getname4")]
        public Object GetName4([FromHeader] ClaimDTO claimDto)
        {
            String name = "";
            if (claimDto != null)
                name = claimDto.FullName;

            return new
            {
                data = name
            };
        }

        [HttpGet("getname")]
        public String GetName()
        {
            return "Bilal Shahzad";
        }

        [HttpGet("getmarks")]
        public int Getmarks(int rollnumber)
        {
            return 100;
        }

        [HttpPost("saveuser")]
        public String Save(StudentDTO dto)
        {
            return "Done";
        }


        [ClaimDTOAttribute]
        [Authorize(Policy = "IsValid")]
        [HttpPost("uploadfile")]
        public void UploadFile(List<IFormFile> UploadedImage, [FromHeader] ClaimDTO claimDto)
        {
            //var files = HttpContext.Request.Form.Files;
            var age = HttpContext.Request.Form["Age"].FirstOrDefault();
            foreach (var file in UploadedImage)
            {
                FileDTO fileDTO = new FileDTO();

                fileDTO.FileActualName = file.FileName;
                fileDTO.FileExt = Path.GetExtension(file.FileName);
                fileDTO.ContentType = file.ContentType;

                //Generate a unique name using Guid
                //fileDTO.FileUniqueName = Guid.NewGuid().ToString();
                //OR
                fileDTO.FileUniqueName = Path.GetRandomFileName();

                //Any data we want to get from claim
                fileDTO.UploadedByID = claimDto.UserID;

                //Get physical path of our folder where we want to save images
                //var rootPath = HttpContext.Current.Server.MapPath("~/UploadedFiles"); // This doesn't work now

                //How to get root path?
                // Hard code root path in configuration?
                //Use IWebHostEnvironment
                var p1 = _env.ContentRootPath;
                var p2 = _env.WebRootPath;

                var fileSavePath = System.IO.Path.Combine(p1, "UploadFiles", fileDTO.FileUniqueName + fileDTO.FileExt);

                // Save the uploaded file to "UploadedFiles" folder
                using (var stream = System.IO.File.Create(fileSavePath))
                {
                    file.CopyTo(stream);
                }

                //Save File Meta data in Database
                DummyDAL.SaveFileInDB(fileDTO);
            }

        }

        [HttpGet("getfiles")]
        public Object GetFiles()
        {
            return new { data = DummyDAL.GetAllFiles() };
        }

        [HttpGet("downloadfile")]
        public IActionResult DownloadFile(String uniqueName)
        {

            var fileDTO = DummyDAL.GetFileByUniqueID(uniqueName);

            if (fileDTO != null)
            {
                System.Net.Mime.ContentDisposition cd = new System.Net.Mime.ContentDisposition
                {
                    FileName = fileDTO.FileActualName,
                    Inline = false  
                };
                Response.Headers.Add("Content-Disposition", cd.ToString());


                /* //OR We could have done like following
                var contentDisposition = new ContentDispositionHeaderValue("attachment");
                contentDisposition.SetHttpFileName("FileDownloadName.jpg");
                Response.Headers[HeaderNames.ContentDisposition] = contentDisposition.ToString();
                */

                //Get Physical Path of Root Folder
                var p1 = _env.ContentRootPath;
                var fileReadPath = System.IO.Path.Combine(p1, "UploadFiles", fileDTO.FileUniqueName + fileDTO.FileExt);


                var image = System.IO.File.OpenRead(fileReadPath);
                return File(image, fileDTO.ContentType);

                //var image = System.IO.File.OpenRead("D:\\nunit.jpg");
                //return File(image, "image/jpeg");

                //return new PhysicalFile(@"C:\test.jpg", "image/jpeg");

            }
            else
            {
                return StatusCode(404);
            }

        }



    }

    public class StudentDTO
    {
        public int ID { get; set; }
        public String Name { get; set; }
        public int Age { get; set; }
    }


    public class ClaimDTO
    {
        public int UserID { get; set; }
        public String FullName { get; set; }
    }
    public class ClaimDTOAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var dto = ((ClaimDTO)context.ActionArguments["claimDto"]);
            var claimsIdentity = context.HttpContext.User.Identity as ClaimsIdentity;
            dto.UserID = Convert.ToInt32(claimsIdentity.Claims.FirstOrDefault(c => c.Type == "userid")?.Value);
            dto.FullName = claimsIdentity.Claims.FirstOrDefault(c => c.Type == "name").Value;
        }
    }
}
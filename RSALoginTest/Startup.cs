using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(RSALoginTest.Startup))]
namespace RSALoginTest
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;

namespace DocumentSealing
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            RequestHeaderMapping requestHeaderMapping = new RequestHeaderMapping("Accept", "text/html", StringComparison.InvariantCultureIgnoreCase, true, "application/json");
            GlobalConfiguration.Configuration.Formatters.JsonFormatter.MediaTypeMappings.Add(requestHeaderMapping);

            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "Root",
                routeTemplate: "{controller}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}

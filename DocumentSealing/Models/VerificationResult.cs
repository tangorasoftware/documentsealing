using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DocumentSealing.Models
{
    public class VerificationResult
    {
        [JsonProperty("acceptedformat")]
        public bool AcceptedFormat { get; set; }

        [JsonProperty("validsignature")]
        public bool ValidSignature { get; set; }

        [JsonProperty("validtimestamp")]
        public bool ValidTimestamp { get; set; }

        [JsonProperty("databag")]
        public string DataBag { get; set; }

        [JsonProperty("error")]
        public string Error { get; set; }
    }
}
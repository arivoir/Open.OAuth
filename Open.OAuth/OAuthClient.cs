using Open.Net.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Open.OAuth
{
    public class OAuthClient
    {
        private static Random nonceGenerator = new Random();

        #region ** authentication

        public static async Task<OAuthToken> GetRequestTokenAsync(string requestTokenUri, string oauthConsumerKey, string oauthConsumerSecret, string callbackUrl, Dictionary<string, string> parameters = null)
        {
            var url = CreateOAuthUrl(requestTokenUri, oauthConsumerKey, oauthConsumerSecret, oauthCallback: callbackUrl, parameters: parameters);
            var client = new HttpClient(HttpMessageHandlerFactory.Default.GetHttpMessageHandler(needsGZipDecompression: true));
            var response = await client.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                Dictionary<string, string> r = ParseResponse(await response.Content.ReadAsStringAsync());
                var oauthCallbackConfirmed = true;
                if (r.ContainsKey("oauth_callback_confirmed"))
                {
                    if (!bool.TryParse(r["oauth_callback_confirmed"], out oauthCallbackConfirmed))
                    {
                        int intBoolean;
                        if (int.TryParse(r["oauth_callback_confirmed"], out intBoolean))
                        {
                            oauthCallbackConfirmed = intBoolean == 1;
                        }
                    }
                }
                return new OAuthToken()
                {
                    Token = r["oauth_token"],
                    TokenSecret = r["oauth_token_secret"],
                    CallbackConfirmed = oauthCallbackConfirmed,
                };
            }
            else
            {
                throw await ProcessException(response.Content);
            }
        }

        public static string GetAuthorizeUrl(string authorizeUri, string oauthConsumerKey, string oauthConsumerSecret, string requestToken)
        {
            return CreateOAuthUrl(authorizeUri, oauthConsumerKey, oauthConsumerSecret, oauthToken: requestToken);
        }

        public static string GetAuthorizeUrl(string authorizeUri, string oauthConsumerKey, string oauthConsumerSecret, string requestToken, string redirectUrl)
        {
            return CreateOAuthUrl(authorizeUri, oauthConsumerKey, oauthConsumerSecret, oauthToken: requestToken, oauthCallback: redirectUrl);
        }

        public static async Task<OAuthToken> GetAccessTokenAsync(string accessTokenUri, string oauthConsumerKey, string oauthConsumerSecret, string oauthToken, string oauthTokenSecret, string oauthVerifier)
        {
            var url = CreateOAuthUrl(accessTokenUri, oauthConsumerKey, oauthConsumerSecret, oauthToken: oauthToken, oauthTokenSecret: oauthTokenSecret, oauthVerifier: oauthVerifier, oauthCallback: null);
            var client = new HttpClient(HttpMessageHandlerFactory.Default.GetHttpMessageHandler(needsGZipDecompression: true));
            var response = await client.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                Dictionary<string, string> r = ParseResponse(await response.Content.ReadAsStringAsync());
                return new OAuthToken()
                {
                    Token = r["oauth_token"],
                    TokenSecret = r["oauth_token_secret"]
                };
            }
            else
            {
                throw await ProcessException(response.Content);
            }
        }

        protected static Dictionary<string, string> ParseResponse(string responseString)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            foreach (var str in responseString.Split('&'))
            {
                var parts = str.Split('=');
                if (parts.Length == 2)
                    parameters[parts[0]] = parts[1];
            }
            return parameters;
        }

        #endregion

        /// <summary>
        /// Generates a new nonce, must be unique for each OAuth request
        /// </summary>
        /// <returns>nonce as string</returns>
        public static string nonce()
        {
            return nonceGenerator.Next(123400, 9999999).ToString();
        }
        /// <summary>
        /// Gets a timestamp in the format required for OAuth
        /// </summary>
        /// <returns>timestamp as string</returns>
        public static string timestamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        /// <summary>
        /// Generates a URL with OAuth parameters
        /// </summary>
        /// <param name="url">base URL for request</param>
        /// <param name="mode">GET or POST, must match HTTP method used</param>
        /// <returns>OAuth compatible URL</returns>
        public static string CreateOAuthUrl(string url,
            string oauthConsumerKey,
            string oauthConsumerSecret,
            string oauthToken = null,
            string oauthTokenSecret = null,
            string oauthCallback = null/*"oob"*/,
            string oauthVerifier = null,
            string mode = "GET",
            IComparer<string> comparer = null,
            Dictionary<string, string> parameters = null)
        {
            var parametersList = parameters == null ? new List<string>() : parameters.Select(pair => string.Format("{0}={1}", pair.Key, Uri.EscapeDataString(pair.Value ?? ""))).ToList();
            parametersList.Add("oauth_consumer_key=" + oauthConsumerKey);
            parametersList.Add("oauth_nonce=" + nonce());
            parametersList.Add("oauth_signature_method=HMAC-SHA1");
            parametersList.Add("oauth_version=1.0");
            if (oauthCallback != null)
                parametersList.Add("oauth_callback=" + Uri.EscapeDataString(oauthCallback));
            parametersList.Add("oauth_timestamp=" + timestamp());
            if (oauthToken != null)
                parametersList.Add("oauth_token=" + oauthToken);
            if (oauthVerifier != null)
                parametersList.Add("oauth_verifier=" + oauthVerifier);
            if (comparer != null)
                parametersList = parametersList.OrderBy(s => s.Substring(0, s.IndexOf("=")), comparer).ToList();
            else
                parametersList = parametersList.OrderBy(s => s.Substring(0, s.IndexOf("="))).ToList();

            string parametersStr = string.Join("&", parametersList.ToArray());

            string baseStr = mode + "&" + Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(parametersStr);

            /* create the crypto class we use to generate a signature for the request */
            var keySrting = oauthConsumerSecret + "&" + (oauthTokenSecret ?? "");
            /* generate the signature and add it to our parameters */
            var keyBytes = Encoding.UTF8.GetBytes(keySrting);
            HMACSHA1 hashAlgorithm = new HMACSHA1(keyBytes);
            byte[] dataBuffer = Encoding.UTF8.GetBytes(baseStr);
            byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);
            var base64StringHash = Convert.ToBase64String(hashBytes);


            var encBase64StringHash = Uri.EscapeDataString(base64StringHash);
            parametersList.Add("oauth_signature=" + encBase64StringHash);
            parametersList = parametersList.OrderBy(s => s.Substring(0, s.IndexOf("="))).ToList();
            return (url + "?" + string.Join("&", parametersList.ToArray()));
        }

        public static string CreateOAuthAuthorizationToken(string url,
            string oauthConsumerKey,
            string oauthConsumerSecret,
            string oauthToken = null,
            string oauthTokenSecret = null,
            string oauthCallback = null/*"oob"*/,
            string oauthVerifier = null,
            string mode = "GET",
            IComparer<string> comparer = null,
            Dictionary<string, string> parameters = null)
        {
            var finalParameters = new Dictionary<string, string>();
            if (parameters != null)
            {
                foreach (var pair in parameters)
                {
                    finalParameters.Add(pair.Key, Uri.EscapeDataString(pair.Value ?? ""));
                }
            }
            finalParameters.Add("oauth_consumer_key", oauthConsumerKey);
            finalParameters.Add("oauth_nonce", nonce());
            finalParameters.Add("oauth_signature_method", "HMAC-SHA1");
            finalParameters.Add("oauth_version", "1.0");
            if (oauthCallback != null)
                finalParameters.Add("oauth_callback", Uri.EscapeDataString(oauthCallback));
            finalParameters.Add("oauth_timestamp", timestamp());
            if (oauthToken != null)
                finalParameters.Add("oauth_token", oauthToken);
            if (oauthVerifier != null)
                finalParameters.Add("oauth_verifier", oauthVerifier);
            IEnumerable<KeyValuePair<string, string>> orderedParameters = null;
            if (comparer != null)
                orderedParameters = finalParameters.OrderBy(s => s.Key, comparer);
            else
                orderedParameters = finalParameters.OrderBy(s => s.Key);
            var parametersList = orderedParameters.Select(pair => string.Format("{0}={1}", pair.Key, pair.Value)).ToArray();
            string parametersStr = string.Join("&", parametersList);

            string baseStr = mode + "&" + Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(parametersStr);

            /* create the crypto class we use to generate a signature for the request */
            var keySrting = oauthConsumerSecret + "&" + (oauthTokenSecret ?? "");
            /* generate the signature and add it to our parameters */
            var keyBytes = Encoding.UTF8.GetBytes(keySrting);
            HMACSHA1 hashAlgorithm = new HMACSHA1(keyBytes);
            byte[] dataBuffer = Encoding.UTF8.GetBytes(baseStr);
            byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);
            var base64StringHash = Convert.ToBase64String(hashBytes);

            var encBase64StringHash = Uri.EscapeDataString(base64StringHash);
            finalParameters.Add("oauth_signature", encBase64StringHash);
            parametersList = finalParameters.OrderBy(s => s.Key).Select(pair => string.Format(@"{0}=""{1}""", pair.Key, pair.Value)).ToArray();
            return @"realm=""" + url + @"""," + string.Join(",", parametersList);
        }
        public static string CreateOAuthAuthorizationHeader(string url,
            string oauthConsumerKey,
            string oauthConsumerSecret,
            string oauthToken = null,
            string oauthTokenSecret = null,
            string oauthCallback = null/*"oob"*/,
            string oauthVerifier = null,
            string mode = "GET",
            IComparer<string> comparer = null,
            Dictionary<string, string> parameters = null)
        {
            return @"OAuth " + CreateOAuthAuthorizationToken(url, oauthConsumerKey, oauthConsumerSecret, oauthToken, oauthTokenSecret, oauthCallback, oauthVerifier, mode, comparer, parameters);
        }


        private static async Task<Exception> ProcessException(HttpContent httpContent)
        {
            return new Exception(await httpContent.ReadAsStringAsync());
        }
    }
}

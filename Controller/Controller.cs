using System.Data;
using System.Text;
using System.Xml;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using System.Xml.Linq;
using System.Xml.Xsl;
using System.Runtime.InteropServices;
using System.Web;
using VulnerableWebApplication.VLAModel;
using System.Reflection.Metadata.Ecma335;


namespace VulnerableWebApplication.VLAController
{
    public class VLAController
    {
        private static string LogFile;

        public static void SetLogFile(string logFile)
        {
            LogFile = logFile;
        }

        public static object VulnerableHelloWorld(string FileName = "english")
        {
            /*
            Retourne le contenu du fichier correspondant à la langue choisie par l'utilisateur
            */

            // ! Group 1 fix: File Traversal
            string basePath = Path.GetFullPath("Languages");
            string fullPath = Path.Combine(basePath, FileName);

            if (!fullPath.StartsWith(basePath)) return Results.Unauthorized();
            return Results.Ok(File.ReadAllText(fullPath));
        }

        public static object VulnerableDeserialize(string Json)
        {
            /*
            Deserialise les données JSON passées en paramètre.
            On enregistre les objets "employé" valides dans un fichier en lecture seule
            */
            string newId = "-1";
            string bufferValidationResult = string.Empty;
            string readOnlyFile = "NewEmployees.txt";

            // Ensure the file exists and is set to read-only
            if (!File.Exists(readOnlyFile))
            {
                File.Create(readOnlyFile).Dispose();
            }
            File.SetAttributes(readOnlyFile, FileAttributes.ReadOnly);

            try
            {
                // Group 1 Fix: Use secure deserialization
                Employee newEmployee = JsonConvert.DeserializeObject<Employee>(Json, new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.None
                });

                if (newEmployee != null && !string.IsNullOrEmpty(newEmployee.Address) && !string.IsNullOrEmpty(newEmployee.Id))
                {
                    // Validate address buffer
                    bufferValidationResult = ValidateBuffer(newEmployee.Address);

                    if (string.IsNullOrEmpty(bufferValidationResult))
                    {
                        // Securely process the ID
                        newId = SecureCodeExecution(newEmployee.Id);

                        // Write employee to the file
                        File.SetAttributes(readOnlyFile, FileAttributes.Normal);
                        using (StreamWriter sw = new StreamWriter(readOnlyFile, true))
                        {
                            sw.Write(JsonConvert.SerializeObject(newEmployee, Newtonsoft.Json.Formatting.Indented));
                        }
                        File.SetAttributes(readOnlyFile, FileAttributes.ReadOnly);
                    }
                }

                return Results.Ok(new
                {
                    FileAttributes = File.GetAttributes(readOnlyFile).ToString(),
                    NewId = newId,
                    IsBufferValid = string.IsNullOrEmpty(bufferValidationResult)
                });
            }
            catch (JsonException jsonEx)
            {
                // Log and handle JSON errors
                Console.Error.WriteLine($"JSON deserialization error: {jsonEx.Message}");
                return Results.BadRequest("Invalid JSON format.");
            }
            catch (Exception ex)
            {
                // Log and handle unexpected errors
                Console.Error.WriteLine($"Unexpected error: {ex.Message}");
                return Results.StatusCode(500, "Internal server error.");
            }
        }

        public static string VulnerableXmlParser(string Xml)
        {
            /*
            Parse les contrats au format XML passées en paramètre et retourne son contenu
            */
            try
            {
                var Xsl = XDocument.Parse(Xml);
                var MyXslTrans = new XslCompiledTransform(enableDebug: true);
                var Settings = new XsltSettings();
                MyXslTrans.Load(Xsl.CreateReader(), Settings, null);
                var DocReader = XDocument.Parse("<doc></doc>").CreateReader();

                var Sb = new StringBuilder();
                var DocWriter = XmlWriter.Create(Sb, new XmlWriterSettings() { ConformanceLevel = ConformanceLevel.Fragment });
                MyXslTrans.Transform(DocReader, DocWriter);

                return Sb.ToString();
            }
            catch (Exception ex)
            {
                XmlReaderSettings ReaderSettings = new XmlReaderSettings();
                // ! Group 1 fix : Disable DTD processing / XMLK Enternal Entitiy Injection
                ReaderSettings.DtdProcessing = DtdProcessing.Prohibit;
                ReaderSettings.XmlResolver = null;
                ReaderSettings.MaxCharactersFromEntities = 6000;

                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(Xml)))
                {
                    XmlReader Reader = XmlReader.Create(stream, ReaderSettings);
                    var XmlDocument = new XmlDocument();
                    XmlDocument.XmlResolver = new XmlUrlResolver();
                    XmlDocument.Load(Reader);

                    return XmlDocument.InnerText;
                }
            }
        }

        public static void VulnerableLogs(string Str, string LogFile)
        {
            /*
            Enregistre la chaine de caractères passée en paramètre dans le fichier de journalisation
            */
            if (Str.Contains("script", StringComparison.OrdinalIgnoreCase)) Str = HttpUtility.HtmlEncode(Str);
            if (!File.Exists(LogFile)) File.WriteAllText(LogFile, Data.GetLogPage());
            string Page = File.ReadAllText(LogFile).Replace("</body>", $"<p>{Str}</p><br>{Environment.NewLine}</body>");
            File.WriteAllText(LogFile, Page);
        }

        public static async Task<object> VulnerableWebRequest(string Uri = "https://localhost:3000/")
        {
            /*
            Effectue une requête web sur la boucle locale
            */
            if (Uri.IsNullOrEmpty()) Uri = "https://localhost:3000/";
            if (Regex.IsMatch(Uri, @"^https://localhost"))
            {
                using HttpClient Client = new();
                Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));

                var Resp = await exec(Client, Uri);
                static async Task<string> exec(HttpClient client, string uri)
                {
                    var Result = client.GetAsync(uri);
                    Result.Result.EnsureSuccessStatusCode();
                    return Result.Result.StatusCode.ToString();
                }
                return Results.Ok(Resp);
            }
            else return Results.Unauthorized();
        }

        public static object VulnerableObjectReference(string Id)
        {
            /*
            Retourne les informations liées à l'ID de l'utilisateur
            Permets aux employés de consulter leurs données personnelles
            */
            var Employee = Data.GetEmployees()?.Where(x => Id == x.Id)?.FirstOrDefault();

            return Results.Ok(Newtonsoft.Json.JsonConvert.SerializeObject(Employee));
        }

        public static object VulnerableCmd(string UserStr)
        {
            /*
            Effectue une requête DNS pour le FQDN passé en paramètre
            */
            if (Regex.Match(UserStr, @"^(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,}(?:.{0,100})$").Success)
            {
                Process Cmd = new Process();
                Cmd.StartInfo.FileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "powershell" : "/bin/sh";
                Cmd.StartInfo.RedirectStandardInput = true;
                Cmd.StartInfo.RedirectStandardOutput = true;
                Cmd.StartInfo.CreateNoWindow = true;
                Cmd.StartInfo.UseShellExecute = false;
                Cmd.Start();
                Cmd.WaitForExit(200);
                // ! Group 1 fix: Command Injection
                if (!Regex.IsMatch(UserStr, @"^[a-zA-Z0-9.-]+$")) throw new ArgumentException("Invalid input.");
                Process.Start(new ProcessStartInfo("nslookup", UserStr) { RedirectStandardOutput = true }).StandardOutput.ReadToEnd();
                Cmd.StandardInput.Flush();
                Cmd.StandardInput.Close();

                return Results.Ok(Cmd.StandardOutput.ReadToEnd());
            }
            else return Results.Unauthorized();
        }

        public static unsafe string VulnerableBuffer(string UserStr)
        {
            /*
            Limite les chaines à 50 caractères
            */
            int BuffSize = 50;
            char* Ptr = stackalloc char[BuffSize], Str = Ptr + BuffSize;
            foreach (var c in UserStr) *Ptr++ = c;

            return new string(Str);
        }

        public static string VulnerableCodeExecution(string UserStr)
        {
            /*
            Retourne un nouvel Id
            */
            if (userInput.Length > 50)
            {
                return "Input exceeds maximum allowed length.";
            }

            return string.Empty;
        }

        public static async Task<IResult> VulnerableHandleFileUpload(IFormFile UserFile, string Header)
        {
            /*
            Permets l'upload de fichier de type SVG
            */
            if (!Header.Contains("10.10.10.256")) return Results.Unauthorized();
            // Group 1 fix: improper file type validation
            if (UserFile.ContentType != "image/svg+xml") throw new InvalidOperationException("Invalid file type.");

            if (UserFile.FileName.EndsWith(".svg")) 
            {
                using var Stream = File.OpenWrite(UserFile.FileName);
                await UserFile.CopyToAsync(Stream);

                return Results.Ok(UserFile.FileName);
            }
            else return Results.Unauthorized();
        }


    }
}

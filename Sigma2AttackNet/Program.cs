using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using Newtonsoft.Json;
using YamlDotNet.Core;
using Parser = CommandLine.Parser;

namespace Sigma2AttackNet
{
    public class Program
    {
        public class Options
        {
            [Option('d', "rules-directory", Required = true, HelpText = "Directory to read rules from")]
            public string RulesDirectory { get; set; }

            [Option('o', "out-file", Required = false, HelpText = "File to write the JSON layer to")]
            public string OutFile { get; set; } = "sigma-coverage.json";

            [Option("no-comment", Required = false, HelpText = "Don't store rule names in comments")]
            public bool NoComment { get; set; } = false;
        }
        public static void Main(string[] args)
        {
            Dictionary<string, List<string>> techs = new Dictionary<string, List<string>>();
            int ruleCount = 0;
            int gradientMax = 0;
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {
                    foreach (var ruleFile in Directory.EnumerateFiles(o.RulesDirectory, "*.yml", SearchOption.AllDirectories))
                    {
                        try
                        {
                            string contents = File.ReadAllText(ruleFile);
                            if (!contents.Contains("tags"))
                            {
                                Console.WriteLine($"Ignoring rule {ruleFile} (no tags)");
                                continue;
                            }

                            contents = contents.Replace(Environment.NewLine + Environment.NewLine,
                                        Environment.NewLine)
                                    .Remove(0, contents.IndexOf("tags", StringComparison.Ordinal));
                            if (contents.Contains("---"))
                                contents = contents.Remove(contents.IndexOf("---", StringComparison.Ordinal));
                            var deserializer = new YamlDotNet.Serialization.Deserializer();
                            var dict = deserializer.Deserialize<Dictionary<string, dynamic>>(contents);
                            if (dict.ContainsKey("tags"))
                            {
                                var tags = dict["tags"];
                                foreach (string tag in tags)
                                {
                                    if (tag.ToLower().StartsWith("attack.t"))
                                    {
                                        var techniqueId = tag.Replace("attack.", "").ToUpper();
                                        ruleCount++;
                                        if (!techs.ContainsKey(techniqueId))
                                            techs[techniqueId] = new List<string>();
                                        techs[techniqueId].Add(ruleFile.Split("\\").Last());
                                        if (techs.Count > gradientMax)
                                            gradientMax = techs.Count;
                                    }
                                }
                            }
                        }
                        catch (YamlException e)
                        {
                            Console.Error.WriteLine($"Ignoring rule {ruleFile} (parsing failed)");
                        }
                    }
                    var entries = techs
                        .ToList()
                        .Select(entry => new
                        {
                            techniqueID = entry.Key,
                            score = entry.Value.Count,
                            comment = (o.NoComment) ? null : string.Join(Environment.NewLine, entry.Value.Select(x => x.Split("/").Last()))
                        });

                    File.WriteAllText(o.OutFile.EndsWith(".json") ? o.OutFile : $"{o.OutFile}.json", JsonConvert.SerializeObject(new
                    {
                        domain = "mitre-enterprise",
                        name = "Sigma rules coverage",
                        gradient = new
                        {
                            colors = new[] { "#a0eab5", "#0f480f" },
                            maxValue = gradientMax,
                            minValue = 0
                        },
                        version = "2.2",
                        techniques = entries
                    }, Formatting.Indented, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    }));
                    Console.WriteLine($"[*] Layer file written in {o.OutFile} ({ruleCount} rules)");
                });
        }
    }
}

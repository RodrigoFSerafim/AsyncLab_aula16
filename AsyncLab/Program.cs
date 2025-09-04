using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Linq;

// =================== Configuração ===================
// Iterações elevadas deixam o trabalho realmente pesado (CPU-bound).
const int PBKDF2_ITERATIONS = 50_000;
const int HASH_BYTES = 32; // 32 = 256 bits
const string CSV_URL = "https://www.gov.br/receitafederal/dados/municipios.csv";
const string OUT_DIR_NAME = "mun_hash_por_uf";
const string BIN_OUT_DIR_NAME = "mun_bin_por_uf";
const string BASE_CSV_NAME = "municipios_base.csv";
const string NEW_CSV_NAME = "municipios_new.csv";

string FormatTempo(long ms)
{
    var ts = TimeSpan.FromMilliseconds(ms);
    return $"{ts.Minutes}m {ts.Seconds}s {ts.Milliseconds}ms";
}

var sw = Stopwatch.StartNew();

string baseDir = Directory.GetCurrentDirectory();
string outRoot = Path.Combine(baseDir, OUT_DIR_NAME);
string outBinRoot = Path.Combine(baseDir, BIN_OUT_DIR_NAME);
string baseCsvPath = Path.Combine(baseDir, BASE_CSV_NAME);
string newCsvPath = Path.Combine(baseDir, NEW_CSV_NAME);

bool baseExiste = File.Exists(baseCsvPath);

if (!baseExiste)
{
    Console.WriteLine("Arquivo base não encontrado. Baixando e salvando como base ...");
    using (var wc = new WebClient())
    {
        wc.Encoding = Encoding.UTF8; // ajuste para ISO-8859-1 se necessário
        wc.DownloadFile(CSV_URL, baseCsvPath);
    }
}
else
{
    Console.WriteLine("Baixando CSV atual para comparação ...");
    using (var wc = new WebClient())
    {
        wc.Encoding = Encoding.UTF8; // ajuste para ISO-8859-1 se necessário
        wc.DownloadFile(CSV_URL, newCsvPath);
    }

    Console.WriteLine("Comparando arquivo baixado com o arquivo base ...");
    var baseLinhas = SafeReadAllLines(baseCsvPath);
    var novasLinhas = SafeReadAllLines(newCsvPath);

    var setBase = new HashSet<string>(baseLinhas, StringComparer.Ordinal);
    var setNovas = new HashSet<string>(novasLinhas, StringComparer.Ordinal);

    var adicionadas = setNovas.Except(setBase).ToList();
    var removidas = setBase.Except(setNovas).ToList();

    if (adicionadas.Count > 0 || removidas.Count > 0)
    {
        string diffPath = Path.Combine(baseDir, $"municipios_diff_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
        using (var fs = new FileStream(diffPath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var swDiff = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            swDiff.WriteLine("CHANGE;LINE");
            foreach (var l in adicionadas) swDiff.WriteLine($"+;{l}");
            foreach (var l in removidas) swDiff.WriteLine($"-;{l}");
        }
        Console.WriteLine($"Diferenças detectadas. Arquivo salvo: {diffPath}");
    }
    else
    {
        Console.WriteLine("Nenhuma diferença entre o arquivo baixado e o base.");
    }
}

Console.WriteLine("Lendo e parseando o CSV ...");
string csvParaLer = File.Exists(newCsvPath) ? newCsvPath : baseCsvPath;
var linhas = SafeReadAllLines(csvParaLer);
if (linhas.Length == 0)
{
    Console.WriteLine("Arquivo CSV vazio.");
    return;
}

int startIndex = 0;
if (linhas[0].IndexOf("IBGE", StringComparison.OrdinalIgnoreCase) >= 0 ||
    linhas[0].IndexOf("UF", StringComparison.OrdinalIgnoreCase) >= 0)
{
    startIndex = 1; // pula cabeçalho
}

var municipios = new List<Municipio>(linhas.Length - startIndex);

for (int i = startIndex; i < linhas.Length; i++)
{
    var linha = (linhas[i] ?? "").Trim();
    if (string.IsNullOrWhiteSpace(linha)) continue;

    var parts = linha.Split(';');
    if (parts.Length < 5) continue;

    municipios.Add(new Municipio
    {
        Tom = Util.San(parts[0]),
        Ibge = Util.San(parts[1]),
        NomeTom = Util.San(parts[2]),
        NomeIbge = Util.San(parts[3]),
        Uf = Util.San(parts[4]).ToUpperInvariant()
    });
}

Console.WriteLine($"Registros lidos: {municipios.Count}");

// Grupo por UF
var porUf = new Dictionary<string, List<Municipio>>(StringComparer.OrdinalIgnoreCase);
foreach (var m in municipios)
{
    if (!porUf.ContainsKey(m.Uf))
        porUf[m.Uf] = new List<Municipio>();
    porUf[m.Uf].Add(m);
}

// Ordena as UFs alfabeticamente e ignora a UF "EX"
var ufsOrdenadas = porUf.Keys
    .Where(uf => !string.Equals(uf, "EX", StringComparison.OrdinalIgnoreCase))
    .OrderBy(uf => uf, StringComparer.OrdinalIgnoreCase)
    .ToList();

// Gera saída
Directory.CreateDirectory(outRoot);
Directory.CreateDirectory(outBinRoot);
Console.WriteLine("Calculando hash por município e gerando arquivos por UF ...");

foreach (var uf in ufsOrdenadas)
{
    var listaUf = porUf[uf];

    // Ordena por Nome preferido para saída consistente
    listaUf.Sort((a, b) => string.Compare(a.NomePreferido, b.NomePreferido, StringComparison.OrdinalIgnoreCase));

    Console.WriteLine($"Processando UF: {uf} ({listaUf.Count} municípios)");
    var swUf = Stopwatch.StartNew();
    string outPath = Path.Combine(outRoot, $"municipios_hash_{uf}.csv");
    using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
    using (var swOut = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
    {
        swOut.WriteLine("TOM;IBGE;NomeTOM;NomeIBGE;UF;Hash");

        var listaJson = new List<object>();
        int count = 0;
        foreach (var m in listaUf)
        {
            // Password: todos os campos concatenados; Salt: IBGE + “pepper” fixo (opcional)
            string password = m.ToConcatenatedString();
            byte[] salt = Util.BuildSalt(m.Ibge);

            // Trabalho pesado real (PBKDF2/SHA-256)
            string hashHex = Util.DeriveHashHex(password, salt, PBKDF2_ITERATIONS, HASH_BYTES);

            swOut.WriteLine($"{m.Tom};{m.Ibge};{m.NomeTom};{m.NomeIbge};{m.Uf};{hashHex}");

            listaJson.Add(new {
                m.Tom,
                m.Ibge,
                m.NomeTom,
                m.NomeIbge,
                m.Uf,
                Hash = hashHex
            });

            count++;
            if (count % 50 == 0 || count == listaUf.Count)
            {
                Console.WriteLine($"  Parcial: {count}/{listaUf.Count} municípios processados para UF {uf} | Tempo parcial: {FormatTempo(swUf.ElapsedMilliseconds)}");
            }
        }
        // Salva JSON
        string jsonPath = Path.Combine(outRoot, $"municipios_hash_{uf}.json");
        var json = JsonSerializer.Serialize(listaJson, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(jsonPath, json, Encoding.UTF8);

        // Saída binária por UF
        string binPath = Path.Combine(outBinRoot, $"municipios_{uf}.bin");
        WriteMunicipiosBin(binPath, listaUf);

        swUf.Stop();
        Console.WriteLine($"UF {uf} concluída. Arquivos gerados: CSV, JSON e BIN. Tempo total UF: {FormatTempo(swUf.ElapsedMilliseconds)}");
    }
}

sw.Stop();
Console.WriteLine();
Console.WriteLine("===== RESUMO =====");
Console.WriteLine($"UFs geradas: {ufsOrdenadas.Count}");
Console.WriteLine($"Pasta de saída: {outRoot}");
Console.WriteLine($"Tempo total: {FormatTempo(sw.ElapsedMilliseconds)} ({sw.Elapsed})");

// ===== Pesquisa interativa =====
Console.WriteLine();
Console.WriteLine("Pesquisar municípios (UF, parte do nome, IBGE ou TOM). Deixe UF vazio para sair.");
while (true)
{
    Console.Write("UF (opcional): ");
    string ufFiltro = (Console.ReadLine() ?? "").Trim();
    if (ufFiltro.Length == 0)
        break;

    Console.Write("Parte do nome (opcional): ");
    string nomeParte = (Console.ReadLine() ?? "").Trim();

    Console.Write("Código (IBGE ou TOM) (opcional): ");
    string cod = (Console.ReadLine() ?? "").Trim();

    var consulta = municipios.AsEnumerable();
    if (!string.IsNullOrWhiteSpace(ufFiltro))
        consulta = consulta.Where(m => string.Equals(m.Uf, ufFiltro, StringComparison.OrdinalIgnoreCase));
    if (!string.IsNullOrWhiteSpace(nomeParte))
        consulta = consulta.Where(m => m.NomePreferido.IndexOf(nomeParte, StringComparison.OrdinalIgnoreCase) >= 0);
    if (!string.IsNullOrWhiteSpace(cod))
        consulta = consulta.Where(m => string.Equals(m.Ibge, cod, StringComparison.OrdinalIgnoreCase) || string.Equals(m.Tom, cod, StringComparison.OrdinalIgnoreCase));

    var resultados = consulta.Take(50).ToList();
    Console.WriteLine($"Encontrados: {resultados.Count} (mostrando até 50)");
    foreach (var m in resultados)
    {
        Console.WriteLine($"UF={m.Uf} | IBGE={m.Ibge} | TOM={m.Tom} | Nome={m.NomePreferido}");
    }
    Console.WriteLine();
}

// ===== Funções auxiliares =====
static string[] SafeReadAllLines(string path)
{
    try { return File.ReadAllLines(path, Encoding.UTF8); }
    catch { return File.ReadAllLines(path, Encoding.GetEncoding(1252)); }
}

static void WriteMunicipiosBin(string path, List<Municipio> lista)
{
    using var fs2 = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
    using var bw = new BinaryWriter(fs2, Encoding.UTF8, leaveOpen: false);
    bw.Write(lista.Count);
    foreach (var m in lista)
    {
        bw.Write(m.Tom ?? "");
        bw.Write(m.Ibge ?? "");
        bw.Write(m.NomeTom ?? "");
        bw.Write(m.NomeIbge ?? "");
        bw.Write(m.Uf ?? "");
    }
}
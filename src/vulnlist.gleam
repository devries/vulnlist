import argv
import directories
import filepath
import gleam/bool
import gleam/dynamic/decode
import gleam/fetch
import gleam/http/request
import gleam/int
import gleam/io
import gleam/javascript/promise
import gleam/json
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp
import simplifile

pub type AppError {
  ArgsError
  CacheError(simplifile.FileError)
  FetchError(fetch.FetchError)
  ParseError(json.DecodeError)
}

pub fn main() {
  let args = argv.load()

  // Execute the pipeline and handle the final outcome in one place
  run(args)
  |> promise.map(fn(result) {
    case result {
      Ok(Nil) -> Nil
      Error(err) -> print_app_error(err)
    }
  })
}

pub fn run(args: argv.Argv) -> promise.Promise(Result(Nil, AppError)) {
  use config <- promise_result_try(parse_args(
    args.arguments,
    args.program,
    Config(filters: [], order: Deadline, force_fetch: False, verbose: False),
  ))

  use json_data <- promise.map_try(get_vulnerabilities(config.force_fetch))
  use vulnlist <- result.try(vulnlist_from_json(json_data))

  vulnlist.vulnerabilities
  |> list.filter(fn(vuln) { list.all(config.filters, matches_filter(_, vuln)) })
  |> list.sort(fn(a: Vuln, b: Vuln) {
    case config.order {
      Deadline -> timestamp.compare(a.due, b.due)
      Creation -> timestamp.compare(a.date_added, b.date_added)
    }
  })
  |> list.index_map(fn(vl, idx) {
    int.to_string(idx + 1)
    <> ". "
    <> vl.vendor_project
    <> " - "
    <> vl.product
    <> " - "
    <> vl.vulnerability_name
    <> " - "
    <> vl.cve_id
    <> "\n\tAdded: "
    <> time_to_date(vl.date_added)
    <> "\n\tDeadline: "
    <> deadline(vl.due)
    <> " ("
    <> time_to_date(vl.due)
    <> ")\n\tACTION: "
    <> vl.action
    <> "\n"
    <> case config.verbose {
      False -> ""
      True -> "\tDESCRIPTION: " <> vl.description <> "\n"
    }
  })
  |> string.join("\n")
  |> io.println

  Ok(Nil)
}

fn print_app_error(error: AppError) -> Nil {
  case error {
    ArgsError -> Nil
    // Usage instructions are already printed during parsing
    CacheError(err) ->
      io.println("Error: Local storage failure (" <> string.inspect(err) <> ")")
    FetchError(_) ->
      io.println(
        "Error: Network failure. Unable to download latest vulnerability feed.",
      )
    ParseError(_) ->
      io.println(
        "Error: Data corruption. The vulnerability catalog could not be parsed.",
      )
  }
}

fn promise_result_try(
  from result: Result(a, e),
  next callback: fn(a) -> promise.Promise(Result(b, e)),
) -> promise.Promise(Result(b, e)) {
  case result {
    Ok(value) -> callback(value)
    Error(error) -> promise.resolve(Error(error))
  }
}

pub type Vuln {
  Vuln(
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: timestamp.Timestamp,
    description: String,
    action: String,
    due: timestamp.Timestamp,
  )
}

pub type VulnList {
  VulnList(
    title: String,
    catalog_version: String,
    date_released: String,
    count: Int,
    vulnerabilities: List(Vuln),
  )
}

pub fn vuln_decoder() -> decode.Decoder(Vuln) {
  use cve_id <- decode.field("cveID", trimmed_string_decoder())
  use vendor_project <- decode.field("vendorProject", trimmed_string_decoder())
  use product <- decode.field("product", trimmed_string_decoder())
  use vuln_name <- decode.field("vulnerabilityName", trimmed_string_decoder())
  use date_added <- decode.field("dateAdded", date_decoder())
  use description <- decode.field("shortDescription", trimmed_string_decoder())
  use action <- decode.field("requiredAction", trimmed_string_decoder())
  use due <- decode.field("dueDate", date_decoder())
  decode.success(Vuln(
    cve_id,
    vendor_project,
    product,
    vuln_name,
    date_added,
    description,
    action,
    due,
  ))
}

pub fn vulnlist_from_json(json_string: String) -> Result(VulnList, AppError) {
  let decoder = {
    use title <- decode.field("title", trimmed_string_decoder())
    use catalog_version <- decode.field(
      "catalogVersion",
      trimmed_string_decoder(),
    )
    use date_released <- decode.field("dateReleased", trimmed_string_decoder())
    use count <- decode.field("count", decode.int)
    use vulnerabilities <- decode.field(
      "vulnerabilities",
      decode.list(vuln_decoder()),
    )
    decode.success(VulnList(
      title,
      catalog_version,
      date_released,
      count,
      vulnerabilities,
    ))
  }

  json.parse(from: json_string, using: decoder)
  |> result.map_error(ParseError)
}

fn get_vulnerabilities(
  force_fetch: Bool,
) -> promise.Promise(Result(String, AppError)) {
  case get_cache_file_path("kev.json") {
    Error(err) -> promise.resolve(Error(err))
    Ok(filepath) ->
      case bool.or(force_fetch, need_vuln_refresh(filepath)) {
        False -> {
          io.println("Note: using cached data")
          simplifile.read(filepath)
          |> report_error("error accessing cache " <> filepath)
          |> result.map_error(CacheError)
          |> promise.resolve
        }
        True -> {
          use body <- promise.map_try(pull_vulnerabilities())
          let _ = simplifile.write(filepath, body)
          Ok(body)
        }
      }
  }
}

fn pull_vulnerabilities() -> promise.Promise(Result(String, AppError)) {
  let assert Ok(req) =
    request.to(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )

  fetch.send(req)
  |> promise.try_await(fetch.read_text_body)
  |> promise.map(fn(resp) {
    resp
    |> result.map(fn(response) { response.body })
    |> result.map_error(FetchError)
  })
}

fn get_cache_file_path(filename: String) -> Result(String, AppError) {
  use base_dir <- result.try(
    directories.cache_dir()
    |> result.replace_error(CacheError(simplifile.Enoent)),
  )

  let app_dir = filepath.join(base_dir, "vulnlist")

  case simplifile.create_directory_all(app_dir) {
    Ok(_) -> Ok(filepath.join(app_dir, filename))
    Error(err) -> Error(CacheError(err))
  }
}

fn need_vuln_refresh(filepath: String) -> Bool {
  let #(current, _) =
    timestamp.to_unix_seconds_and_nanoseconds(timestamp.system_time())

  case simplifile.file_info(filepath) {
    Error(_) -> True
    Ok(info) -> info.mtime_seconds < { current - 3600 }
  }
}

fn report_error(r: Result(a, b), message: String) -> Result(a, b) {
  use ev <- result.try_recover(r)
  io.println(message <> ": " <> string.inspect(ev))
  Error(ev)
}

fn trimmed_string_decoder() {
  decode.string
  |> decode.map(string.trim)
}

fn date_decoder() -> decode.Decoder(timestamp.Timestamp) {
  use trimmed_string <- decode.then(trimmed_string_decoder())
  let values =
    string.split(trimmed_string, "-")
    |> list.map(int.parse)
    |> result.all

  case values {
    Ok([year, month_int, day]) -> {
      case calendar.month_from_int(month_int) {
        Ok(month) -> {
          let dt = calendar.Date(year, month, day)
          // let #(_, tod) =
          //   timestamp.system_time()
          //   |> timestamp.to_calendar(calendar.local_offset())
          let tod = calendar.TimeOfDay(0, 0, 0, 0)

          decode.success(timestamp.from_calendar(
            dt,
            tod,
            calendar.local_offset(),
          ))
        }

        _ ->
          decode.failure(
            timestamp.from_unix_seconds(0),
            "YYYY-MM-DD with MM between 01 and 12",
          )
      }
    }
    _ -> decode.failure(timestamp.from_unix_seconds(0), "YYYY-MM-DD")
  }
}

fn time_to_date(t: timestamp.Timestamp) -> String {
  let #(day, _) = timestamp.to_calendar(t, calendar.local_offset())
  digitstring(day.year, 4)
  <> "-"
  <> digitstring(calendar.month_to_int(day.month), 2)
  <> "-"
  <> digitstring(day.day, 2)
}

fn digitstring(v: Int, digits: Int) -> String {
  int.to_string(v)
  |> string.pad_start(to: digits, with: "0")
}

fn days_until(t: timestamp.Timestamp) -> Int {
  let diff =
    duration.to_milliseconds(timestamp.difference(timestamp.system_time(), t))

  case diff > 0 {
    True -> { diff + 86_400_000 } / 86_400_000
    False -> diff / 86_400_000
  }
}

fn deadline(t: timestamp.Timestamp) -> String {
  let du = days_until(t)
  case du {
    n if n > 1 -> int.to_string(n) <> " days"
    1 -> "1 day"
    0 -> "TODAY"
    _ -> "OVERDUE"
  }
}

pub type Filter {
  New
  Cve(search_term: String)
  Any(search_term: String)
  Vendor(search_term: String)
}

pub type SortOrder {
  Deadline
  Creation
}

pub type Config {
  Config(
    filters: List(Filter),
    order: SortOrder,
    force_fetch: Bool,
    verbose: Bool,
  )
}

fn parse_args(
  args: List(String),
  cmd: String,
  config: Config,
) -> Result(Config, AppError) {
  case args {
    [] -> Ok(config)
    ["-n", ..rest] | ["--new", ..rest] -> {
      parse_args(rest, cmd, Config(..config, filters: [New, ..config.filters]))
    }
    ["-c", search_term, ..rest] | ["--cve", search_term, ..rest] -> {
      parse_args(
        rest,
        cmd,
        Config(..config, filters: [Cve(search_term), ..config.filters]),
      )
    }
    ["-a", search_term, ..rest] | ["--any", search_term, ..rest] -> {
      parse_args(
        rest,
        cmd,
        Config(..config, filters: [Any(search_term), ..config.filters]),
      )
    }
    ["-v", search_term, ..rest] | ["--vendor", search_term, ..rest] -> {
      parse_args(
        rest,
        cmd,
        Config(..config, filters: [Vendor(search_term), ..config.filters]),
      )
    }
    ["-d", ..rest] | ["--added", ..rest] -> {
      parse_args(rest, cmd, Config(..config, order: Creation))
    }
    ["-f", ..rest] | ["--fetch", ..rest] -> {
      parse_args(rest, cmd, Config(..config, force_fetch: True))
    }
    ["-V", ..rest] | ["--verbose", ..rest] -> {
      parse_args(rest, cmd, Config(..config, verbose: True))
    }
    ["-h", ..] | ["--help", ..] -> {
      usage(cmd)
      Error(ArgsError)
    }
    [_, ..] -> {
      usage(cmd)
      Error(ArgsError)
    }
  }
}

fn matches_filter(filter: Filter, vulnerability: Vuln) -> Bool {
  case filter {
    New -> {
      let limit = timestamp.add(timestamp.system_time(), duration.hours(-24))
      case timestamp.compare(vulnerability.due, limit) {
        order.Lt -> False
        _ -> True
      }
    }
    Cve(term) -> {
      string.lowercase(vulnerability.cve_id)
      |> string.contains(string.lowercase(term))
    }
    Any(term) -> {
      let combined =
        string.lowercase(vulnerability.vendor_project)
        <> ":"
        <> string.lowercase(vulnerability.product)
        <> ":"
        <> string.lowercase(vulnerability.description)
      string.contains(combined, string.lowercase(term))
    }
    Vendor(term) -> {
      string.lowercase(vulnerability.vendor_project)
      |> string.contains(string.lowercase(term))
    }
  }
}

fn usage(command: String) -> Nil {
  io.println(
    "Usage: "
    <> filepath.base_name(command)
    <> " [-n | --new] [ -a | --any <search_term>] [ -c | --cve <search_term>] [ -v || --vendor <search_term>]"
    <> "\n                  [-d | --added] [-f | --fetch] [-V | --verbose]",
  )
  io.println("       -n | --new                  - Only show not overdue")
  io.println(
    "       -a | --any <search_term>    - Case insensitive search for search term in vendor, product, or description",
  )
  io.println(
    "       -c | --cve <search_term>    - Case insensitive search for search term in CVE ID",
  )
  io.println(
    "       -v | --vendor <search_term> - Case insensitive search for search term in CVE ID",
  )
  io.println("       -d | --added                - Sort by date added")
  io.println("       -f | --fetch                - Force data refresh")
  io.println("       -V | --verbose              - Verbose output")
  io.println("       -h | --help                 - Show this help")
  Nil
}

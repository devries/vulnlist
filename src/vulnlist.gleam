import argv
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp

pub fn main() {
  let args = argv.load()

  use vuln_filters <- result.try(create_filter(args))

  use json_data <- result.try(get_vulnerabilities())
  use vulnlist <- result.try({
    vulnlist_from_json(json_data)
    |> report_error("unable to parse data")
    |> result.replace_error(Nil)
  })

  vulnlist.vulnerabilities
  |> list.filter(vuln_filters)
  |> list.sort(fn(a: Vuln, b: Vuln) { timestamp.compare(a.due, b.due) })
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
  })
  |> string.join("\n")
  |> io.println

  Ok(Nil)
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

pub fn vulnlist_from_json(
  json_string: String,
) -> Result(VulnList, json.DecodeError) {
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
}

fn get_vulnerabilities() -> Result(String, Nil) {
  let assert Ok(req) =
    request.to(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )

  use response <- result.try(
    req
    |> httpc.send
    |> report_error("unable to send query")
    |> result.replace_error(Nil),
  )
  Ok(response.body)
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

fn create_filter(args: argv.Argv) -> Result(fn(Vuln) -> Bool, Nil) {
  use subfilters <- result.try(
    create_filter_acc(args.arguments, args.program, []),
  )
  let res = fn(v: Vuln) -> Bool { list.all(subfilters, fn(f) { f(v) }) }

  Ok(res)
}

fn create_filter_acc(
  args: List(String),
  cmd: String,
  acc: List(fn(Vuln) -> Bool),
) -> Result(List(fn(Vuln) -> Bool), Nil) {
  case args {
    [] -> Ok(acc)
    ["-n", ..rest] | ["--new", ..rest] -> {
      create_filter_acc(rest, cmd, [filter_out_overdue, ..acc])
    }
    ["-c", search_term, ..rest] | ["--cve", search_term, ..rest] -> {
      create_filter_acc(rest, cmd, [filter_cve(_, search_term), ..acc])
    }
    ["-a", search_term, ..rest] | ["--any", search_term, ..rest] -> {
      create_filter_acc(rest, cmd, [filter_any(_, search_term), ..acc])
    }
    ["-v", search_term, ..rest] | ["--vendor", search_term, ..rest] -> {
      create_filter_acc(rest, cmd, [filter_vendor(_, search_term), ..acc])
    }
    ["-h", ..] | ["--help", ..] -> {
      usage(cmd)
      Error(Nil)
    }
    [_, ..] -> {
      usage(cmd)
      Error(Nil)
    }
  }
}

fn filter_out_overdue(a: Vuln) -> Bool {
  let limit = timestamp.add(timestamp.system_time(), duration.hours(-24))
  case timestamp.compare(a.due, limit) {
    order.Lt -> False
    order.Eq -> True
    order.Gt -> True
  }
}

fn filter_cve(a: Vuln, cve: String) -> Bool {
  string.lowercase(a.cve_id)
  |> string.contains(string.lowercase(cve))
}

fn filter_any(a: Vuln, s: String) -> Bool {
  let v =
    string.lowercase(a.vendor_project)
    <> ":"
    <> string.lowercase(a.product)
    <> ":"
    <> string.lowercase(a.description)
  string.contains(v, string.lowercase(s))
}

fn filter_vendor(a: Vuln, s: String) -> Bool {
  string.lowercase(a.vendor_project)
  |> string.contains(string.lowercase(s))
}

fn usage(command: String) -> Nil {
  io.println(
    "Usage: "
    <> command
    <> " [-n | --new] [ -a | --any <search_term>] [ -c | --cve <search_term>] [ -v || --vendor <search_term>]",
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
  io.println("       -h | --help                 - Show this help")
  Nil
}

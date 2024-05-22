import argv
import birl
import birl/duration
import gleam/dynamic
import gleam/erlang
import gleam/erlang/atom
import gleam/hackney
import gleam/http/request
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/order
import gleam/result
import gleam/string

pub fn main() {
  // This is so that gleescript starts all the application dependencies
  // of this program
  let _ =
    erlang.ensure_all_started(application: atom.create_from_string("vulnlist"))

  // This is the actual program
  let args = argv.load()

  use _ <- result.try({
    case args.arguments {
      [] -> Ok(Nil)
      ["all"] -> Ok(Nil)
      _ -> {
        io.println("Usage: <command> [all]")
        Error(Nil)
      }
    }
  })

  use json_data <- result.try(get_vulnerabilities())
  use vulnlist <- result.try({
    vulnlist_from_json(json_data)
    |> report_error("unable to parse data")
    |> result.nil_error
  })

  vulnlist.vulnerabilities
  |> list.filter(fn(a: Vuln) {
    let limit = birl.add(birl.now(), duration.hours(-1))
    case args.arguments, birl.compare(a.due, limit) {
      ["all"], _ -> True
      _, order.Lt -> False
      _, order.Eq -> True
      _, order.Gt -> True
    }
  })
  |> list.sort(fn(a: Vuln, b: Vuln) { birl.compare(a.due, b.due) })
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
    date_added: birl.Time,
    description: String,
    action: String,
    due: birl.Time,
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

pub fn vuln_decoder(
  v: dynamic.Dynamic,
) -> Result(Vuln, List(dynamic.DecodeError)) {
  dynamic.decode8(
    Vuln,
    dynamic.field("cveID", of: trimmed_string),
    dynamic.field("vendorProject", of: trimmed_string),
    dynamic.field("product", of: trimmed_string),
    dynamic.field("vulnerabilityName", of: trimmed_string),
    dynamic.field("dateAdded", of: decode_date),
    dynamic.field("shortDescription", of: trimmed_string),
    dynamic.field("requiredAction", of: trimmed_string),
    dynamic.field("dueDate", of: decode_date),
  )(v)
}

pub fn vulnlist_from_json(
  json_string: String,
) -> Result(VulnList, json.DecodeError) {
  let decoder =
    dynamic.decode5(
      VulnList,
      dynamic.field("title", of: trimmed_string),
      dynamic.field("catalogVersion", of: trimmed_string),
      dynamic.field("dateReleased", of: trimmed_string),
      dynamic.field("count", of: dynamic.int),
      dynamic.field("vulnerabilities", of: dynamic.list(vuln_decoder)),
    )

  json.decode(from: json_string, using: decoder)
}

fn get_vulnerabilities() -> Result(String, Nil) {
  let assert Ok(req) =
    request.to(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )

  use response <- result.try(
    req
    |> hackney.send
    |> report_error("unable to send query")
    |> result.nil_error,
  )
  Ok(response.body)
}

fn report_error(r: Result(a, b), message: String) -> Result(a, b) {
  use ev <- result.try_recover(r)
  io.println(message <> ": " <> string.inspect(ev))
  Error(ev)
}

fn trimmed_string(
  from data: dynamic.Dynamic,
) -> Result(String, List(dynamic.DecodeError)) {
  use untrimmed <- result.try(dynamic.string(from: data))
  Ok(string.trim(untrimmed))
}

fn decode_date(
  from data: dynamic.Dynamic,
) -> Result(birl.Time, List(dynamic.DecodeError)) {
  use trimmed_string <- result.try(trimmed_string(from: data))

  let err = [
    dynamic.DecodeError(
      "String of form YYYY-MM-DD",
      found: trimmed_string,
      path: [],
    ),
  ]

  use values <- result.try(
    string.split(trimmed_string, "-")
    |> list.map(int.parse)
    |> result.all
    |> result.replace_error(err),
  )
  case values {
    [year, month, day] -> {
      let t =
        birl.now()
        |> birl.set_day(birl.Day(year, month, day))

      Ok(t)
    }
    _ -> Error(err)
  }
}

fn time_to_date(t: birl.Time) -> String {
  let day = birl.get_day(t)
  digitstring(day.year, 4)
  <> "-"
  <> digitstring(day.month, 2)
  <> "-"
  <> digitstring(day.date, 2)
}

fn digitstring(v: Int, digits: Int) -> String {
  int.to_string(v)
  |> string.pad_left(to: digits, with: "0")
}

fn days_until(t: birl.Time) -> Int {
  birl.difference(t, birl.now())
  |> duration.blur_to(duration.Day)
}

fn deadline(t: birl.Time) -> String {
  case days_until(t) {
    n if n > 1 -> int.to_string(n) <> " days"
    1 -> "1 day"
    0 -> "TODAY"
    _ -> "OVERDUE"
  }
}

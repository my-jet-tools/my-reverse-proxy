use std::net::IpAddr;

/// A list of `country_white_lists`: the countries a client may come from. The country of a client
/// is the one the country database of [`crate::ip_db`] gives for the address of its connection -
/// an address it has no country for (a private one, the loopback, one it does not know) is in no
/// list, and is refused by every one.
#[derive(Debug)]
pub struct CountryWhiteList {
    id: String,
    /// ISO 3166 codes of two letters, upper case - as `ip_db` gives them. Sorted, no repeats.
    countries: Vec<[u8; 2]>,
}

impl CountryWhiteList {
    /// `countries`: as written in the settings - codes of two letters (`UA`) or of three (`UKR`),
    /// any letter case. A code which is not a country refuses the list, and so does a list with
    /// no country at all: it would let nobody in, which is not what anybody writes it for.
    pub fn new(id: &str, countries: &[String]) -> Result<Self, String> {
        let mut codes = Vec::with_capacity(countries.len());

        for country in countries {
            let code = rust_common::country_code::CountryCode::parse(country.trim()).map_err(|_| {
                format!(
                    "country_white_lists.{id}: '{country}' is not a country code. Write the ISO \
                     3166 code of two letters (UA) or of three (UKR)"
                )
            })?;

            let iso2 = code.as_iso2_str().as_bytes();
            codes.push([iso2[0], iso2[1]]);
        }

        if codes.is_empty() {
            return Err(format!(
                "country_white_lists.{id} names no country: it would let nobody in"
            ));
        }

        codes.sort_unstable();
        codes.dedup();

        Ok(Self {
            id: id.to_string(),
            countries: codes,
        })
    }

    /// The codes of two letters, sorted.
    pub fn countries(&self) -> impl Iterator<Item = &str> {
        self.countries
            .iter()
            .map(|code| std::str::from_utf8(code).unwrap_or_default())
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        match country_of(ip) {
            Some(country) => self.countries.binary_search(&country).is_ok(),
            None => false,
        }
    }

    /// Why the client at `ip` is refused, for a log - `None`: it is not.
    pub fn refusal(&self, ip: IpAddr) -> Option<String> {
        match country_of(ip) {
            Some(country) if self.countries.binary_search(&country).is_ok() => None,
            Some(country) => Some(format!(
                "client country {} is not in country list '{}'",
                std::str::from_utf8(&country).unwrap_or_default(),
                self.id
            )),
            None => Some(format!(
                "client address has no country (a private address, or one the country database \
                 does not know), so it is not in country list '{}'",
                self.id
            )),
        }
    }
}

/// The country a test client comes from. Every test connects from the loopback, which has no
/// country: in the tests it is of this one, so a list can let a test in as well as keep it out.
#[cfg(test)]
pub const LOOPBACK_COUNTRY_IN_TESTS: &str = "UA";

fn country_of(ip: IpAddr) -> Option<[u8; 2]> {
    // An IPv4 client of a dual-stack listener comes as `::ffff:a.b.c.d`: it is looked up as the
    // IPv4 address it is.
    let ip = ip.to_canonical();

    #[cfg(test)]
    if ip.is_loopback() {
        let code = LOOPBACK_COUNTRY_IN_TESTS.as_bytes();
        return Some([code[0], code[1]]);
    }

    crate::ip_db::lookup_country(ip)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn list(countries: &[&str]) -> Result<CountryWhiteList, String> {
        let countries: Vec<String> = countries.iter().map(|itm| itm.to_string()).collect();
        CountryWhiteList::new("the_list", &countries)
    }

    const GOOGLE_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    #[test]
    fn a_code_of_two_letters_or_of_three_in_any_case_is_the_same_country() {
        let list = list(&["ua", "UKR", "Us", " DE "]).unwrap();

        assert_eq!(list.countries().collect::<Vec<_>>(), ["DE", "UA", "US"]);
    }

    #[test]
    fn a_code_which_is_not_a_country_refuses_the_list() {
        let err = list(&["UA", "XX"]).unwrap_err();

        assert!(err.contains("country_white_lists.the_list"), "{err}");
        assert!(err.contains("'XX' is not a country code"), "{err}");
    }

    #[test]
    fn a_list_with_no_country_is_refused() {
        let err = list(&[]).unwrap_err();

        assert!(err.contains("names no country"), "{err}");
    }

    #[test]
    fn a_client_is_let_in_by_the_country_of_its_address() {
        assert!(list(&["US"]).unwrap().allows(GOOGLE_DNS));
        assert!(list(&["USA"]).unwrap().allows(GOOGLE_DNS));
        assert!(!list(&["UA", "DE"]).unwrap().allows(GOOGLE_DNS));
    }

    #[test]
    fn an_ipv4_client_of_a_dual_stack_listener_has_the_country_of_its_ipv4_address() {
        let mapped = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());

        assert!(list(&["US"]).unwrap().allows(mapped));
        assert!(!list(&["DE"]).unwrap().allows(mapped));
    }

    #[test]
    fn a_private_address_has_no_country_and_is_refused_by_every_list() {
        let list = list(&["US", "UA", "DE"]).unwrap();

        for ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            assert!(!list.allows(ip), "{ip}");

            let refusal = list.refusal(ip).unwrap();
            assert!(refusal.contains("has no country"), "{refusal}");
        }
    }

    #[test]
    fn the_refusal_names_the_country_and_the_list() {
        assert_eq!(
            list(&["DE"]).unwrap().refusal(GOOGLE_DNS).unwrap(),
            "client country US is not in country list 'the_list'"
        );
        assert_eq!(list(&["US"]).unwrap().refusal(GOOGLE_DNS), None);
    }
}

use arrayvec::{ArrayString, ArrayVec};
use core::fmt::Write;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{
    CenteredInfo, CenteredInfoStyle, Field, InfoLongPress, NbglGenericReview, NbglPageContent,
    TagValueList, TuneIndex,
};
use otp_core::record::Record;

const MAX_ACCOUNTS: usize = 64;

pub fn review_import(comm: &mut Comm, records: &[Record], restoring: bool) -> bool {
    if records.is_empty() || records.len() > MAX_ACCOUNTS {
        return false;
    }
    let n = records.len();
    let plural = if n == 1 { "account" } else { "accounts" };
    let verb = if restoring { "Restore" } else { "Import" };
    let mut title = ArrayString::<40>::new();
    let _ = write!(title, "{verb} {n} {plural}?");
    let mut finish = ArrayString::<40>::new();
    let _ = write!(finish, "Save {n} {plural}");
    let reject = if restoring {
        "Reject restore"
    } else {
        "Reject import"
    };

    let fields: ArrayVec<Field, MAX_ACCOUNTS> = records
        .iter()
        .map(|r| Field {
            name: r.issuer.as_str(),
            value: r.account.as_str(),
        })
        .collect();

    NbglGenericReview::new()
        .add_content(NbglPageContent::CenteredInfo(CenteredInfo::new(
            &title,
            "Review each account before saving it to this device.",
            "",
            None,
            false,
            CenteredInfoStyle::LargeCaseBoldInfo,
            0,
        )))
        .add_content(NbglPageContent::TagValueList(TagValueList::new(
            &fields, 0, false, false,
        )))
        .add_content(NbglPageContent::InfoLongPress(InfoLongPress::new(
            &finish,
            None,
            "Hold to save",
            TuneIndex::Success,
        )))
        .show(comm, reject)
}

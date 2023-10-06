
pub fn return_if_equal<T>(a: T, b: T) -> Option<T>
where T: Eq
{
    if a == b {
        Some(a)
    } else {
        None
    }
}


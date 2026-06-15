use proxlet::connector::Target;

#[test]
fn formats_ipv6_authority() {
    assert_eq!(Target::new("::1", 443).authority(), "[::1]:443");
}

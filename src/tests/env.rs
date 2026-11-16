use super::parse;

#[test]
fn reads_names_values_quotes_and_comments() {
    let text = "# a comment\n\nVAXELIUM_PEERS=127.0.0.1:7878,203.0.113.5:7878 # two servers\n\
                export VAXELIUM_AUTH=\"127.0.0.1:7900\"\nNAME='x y'\nEMPTY=\nnot a setting\n";
    assert_eq!(
        parse(text),
        vec![
            (
                "VAXELIUM_PEERS".to_string(),
                "127.0.0.1:7878,203.0.113.5:7878".to_string()
            ),
            ("VAXELIUM_AUTH".to_string(), "127.0.0.1:7900".to_string()),
            ("NAME".to_string(), "x y".to_string()),
            ("EMPTY".to_string(), String::new()),
        ]
    );
}

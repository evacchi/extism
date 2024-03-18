#[cfg(test)]
mod tests {
    use crate::*;

    fn run_thread(p: Pool<String>, i: u64) -> std::thread::JoinHandle<()> {
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(i));
            let s: String = p
                .get(&"test".to_string(), std::time::Duration::from_secs(5))
                .unwrap()
                .unwrap()
                .call("count_vowels", "abc")
                .unwrap();
            println!("{}", s);
        });
        t
    }

    #[test]
    fn test_threads() {
        let pool: Pool<String> = Pool::new(2);

        let test = "test".to_string();
        pool.add(test.clone(), || {
            extism::Plugin::new(
                extism::Manifest::new([extism::Wasm::file("../wasm/code.wasm")]),
                vec![],
                true,
            )
        });

        let mut threads = vec![];
        threads.push(run_thread(pool.clone(), 1000));
        threads.push(run_thread(pool.clone(), 1000));
        threads.push(run_thread(pool.clone(), 500));
        threads.push(run_thread(pool.clone(), 0));

        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(pool.count(&test), 2);
    }
}

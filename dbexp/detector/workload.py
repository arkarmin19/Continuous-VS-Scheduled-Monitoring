        kinds = ["classic", "evasive", "phish"]
        gap = a.duration * 0.8 / a.attacks
        time.sleep(a.duration * 0.1)
        for i in range(a.attacks):
            kind = kinds[i % 3]
            if kind == "phish":
                c.phish_episode(i)
            else:
                c.sqli(kind == "evasive", i // 3)
            time.sleep(max(0.0, gap * random.uniform(0.7, 1.3)))

    threads = [threading.Thread(target=worker) for _ in range(a.workers)]
    threads.append(threading.Thread(target=attacker))
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    Store(a.db).add_http_rows(results)
    print(f"run={a.run_id}: {len(results)} HTTP requests in {time.time() - t0:.0f}s "
          f"({len(results) / (time.time() - t0):.1f} req/s)")


if __name__ == "__main__":
    main()

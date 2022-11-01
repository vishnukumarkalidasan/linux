run_memtier_benchmark()
    {
        # populate dataset
        memtier_benchmark/memtier_benchmark -s 127.0.0.1 -p 11211 \
            -P memcache_binary -n allkeys -t 1 -c 1 --ratio 1:0 --pipeline 8 \
            --key-minimum=1 --key-maximum=$2 --key-pattern=P:P \
            -d 1000

        # access dataset using Guassian pattern
        memtier_benchmark/memtier_benchmark -s 127.0.0.1 -p 11211 \
            -P memcache_binary --test-time $1 -t 1 -c 1 --ratio 0:1 \
            --pipeline 8 --key-minimum=1 --key-maximum=$2 \
            --key-pattern=G:G --randomize --distinct-client-seed

        # collect results
    }

    run_duration_secs=3600
    max_key=8000000

    run_memtier_benchmark $run_duration_secs $max_key

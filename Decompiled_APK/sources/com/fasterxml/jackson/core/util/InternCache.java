package com.fasterxml.jackson.core.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/* loaded from: classes.dex */
public final class InternCache extends ConcurrentHashMap<String, String> {
    public static final InternCache instance = new InternCache();
    private final ReentrantLock lock;

    public InternCache() {
        this(280, 0.8f, 4);
    }

    public String intern(String str) {
        String str2 = get(str);
        if (str2 != null) {
            return str2;
        }
        if (size() >= 280 && this.lock.tryLock()) {
            try {
                if (size() >= 280) {
                    clear();
                }
            } finally {
                this.lock.unlock();
            }
        }
        String strIntern = str.intern();
        put(strIntern, strIntern);
        return strIntern;
    }

    public InternCache(int i, float f, int i2) {
        super(i, f, i2);
        this.lock = new ReentrantLock();
    }
}

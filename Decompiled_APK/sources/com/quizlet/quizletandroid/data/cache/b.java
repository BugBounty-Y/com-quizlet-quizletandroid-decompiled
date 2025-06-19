package com.quizlet.quizletandroid.data.cache;

import com.google.firebase.crashlytics.internal.metadata.q;
import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes3.dex */
public final class b extends a {
    public final AtomicLong b;
    public final long c;
    public final Map d;

    public b(File file) {
        super(file);
        this.d = Collections.synchronizedMap(new HashMap());
        this.c = 5242880L;
        this.b = new AtomicLong();
        new Thread(new q(this, 14)).start();
    }

    @Override // com.quizlet.quizletandroid.data.cache.a
    public final void a() {
        this.d.clear();
        this.b.set(0L);
        super.a();
    }

    @Override // com.quizlet.quizletandroid.data.cache.a
    public final File b(String str) {
        File file = new File(this.a, String.valueOf(str.hashCode()));
        long jCurrentTimeMillis = System.currentTimeMillis();
        Long lValueOf = Long.valueOf(jCurrentTimeMillis);
        file.setLastModified(jCurrentTimeMillis);
        this.d.put(file, lValueOf);
        return file;
    }

    @Override // com.quizlet.quizletandroid.data.cache.a
    public final void c(File file, String str) {
        File file2;
        long length;
        long length2 = file.length();
        long jAddAndGet = this.b.get();
        while (jAddAndGet + length2 > this.c) {
            if (this.d.isEmpty()) {
                length = -1;
            } else {
                Set<Map.Entry> setEntrySet = this.d.entrySet();
                synchronized (this.d) {
                    try {
                        file2 = null;
                        Long l = null;
                        for (Map.Entry entry : setEntrySet) {
                            if (file2 == null) {
                                file2 = (File) entry.getKey();
                                l = (Long) entry.getValue();
                            } else {
                                Long l2 = (Long) entry.getValue();
                                if (l2.longValue() < l.longValue()) {
                                    file2 = (File) entry.getKey();
                                    l = l2;
                                }
                            }
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                length = 0;
                if (file2 != null) {
                    if (file2.exists()) {
                        length = file2.length();
                        if (file2.delete()) {
                            this.d.remove(file2);
                        }
                    } else {
                        this.d.remove(file2);
                    }
                }
            }
            if (length == -1) {
                break;
            } else {
                jAddAndGet = this.b.addAndGet(-length);
            }
        }
        this.b.addAndGet(length2);
        long jCurrentTimeMillis = System.currentTimeMillis();
        Long lValueOf = Long.valueOf(jCurrentTimeMillis);
        file.setLastModified(jCurrentTimeMillis);
        this.d.put(file, lValueOf);
    }
}

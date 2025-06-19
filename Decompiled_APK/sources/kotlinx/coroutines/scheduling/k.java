package kotlinx.coroutines.scheduling;

import java.util.concurrent.TimeUnit;
import kotlinx.coroutines.internal.s;

/* loaded from: classes3.dex */
public abstract class k {
    public static final String a;
    public static final long b;
    public static final int c;
    public static final int d;
    public static final long e;
    public static final g f;

    static {
        String property;
        int i = s.a;
        try {
            property = System.getProperty("kotlinx.coroutines.scheduler.default.name");
        } catch (SecurityException unused) {
            property = null;
        }
        if (property == null) {
            property = "DefaultDispatcher";
        }
        a = property;
        b = kotlinx.coroutines.internal.b.j("kotlinx.coroutines.scheduler.resolution.ns", 100000L, 1L, Long.MAX_VALUE);
        int i2 = s.a;
        if (i2 < 2) {
            i2 = 2;
        }
        c = kotlinx.coroutines.internal.b.k(i2, 8, "kotlinx.coroutines.scheduler.core.pool.size");
        d = kotlinx.coroutines.internal.b.k(2097150, 4, "kotlinx.coroutines.scheduler.max.pool.size");
        e = TimeUnit.SECONDS.toNanos(kotlinx.coroutines.internal.b.j("kotlinx.coroutines.scheduler.keep.alive.sec", 60L, 1L, Long.MAX_VALUE));
        f = g.a;
    }
}

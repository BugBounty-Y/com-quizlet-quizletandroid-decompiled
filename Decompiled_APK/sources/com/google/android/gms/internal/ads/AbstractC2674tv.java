package com.google.android.gms.internal.ads;

import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: com.google.android.gms.internal.ads.tv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2674tv extends AbstractC2246jw implements com.google.common.util.concurrent.e {
    public static final Object d = new Object();
    public static final Wv e = new Wv(AbstractC2460ov.class, 0);
    public static final boolean f;
    public static final AbstractC2457os g;
    public volatile Object a;
    public volatile C2331lv b;
    public volatile C2631sv c;

    static {
        boolean z;
        AbstractC2457os c2546qv;
        Throwable th;
        Throwable th2;
        try {
            z = Boolean.parseBoolean(System.getProperty("guava.concurrent.generate_cancellation_cause", "false"));
        } catch (SecurityException unused) {
            z = false;
        }
        f = z;
        String property = System.getProperty("java.runtime.name", "");
        Throwable th3 = null;
        if (property == null || property.contains("Android")) {
            try {
                c2546qv = new C2588rv();
            } catch (Error | Exception e2) {
                try {
                    c2546qv = new C2503pv();
                } catch (Error | Exception e3) {
                    th3 = e3;
                    c2546qv = new C2546qv();
                }
                th = th3;
                th2 = e2;
            }
        } else {
            try {
                c2546qv = new C2503pv();
            } catch (NoClassDefFoundError unused2) {
                c2546qv = new C2546qv();
            }
        }
        th = null;
        th2 = null;
        g = c2546qv;
        if (th != null) {
            Wv wv = e;
            Logger loggerA = wv.a();
            Level level = Level.SEVERE;
            loggerA.logp(level, "com.google.common.util.concurrent.AbstractFutureState", "<clinit>", "UnsafeAtomicHelper is broken!", th2);
            wv.a().logp(level, "com.google.common.util.concurrent.AbstractFutureState", "<clinit>", "AtomicReferenceFieldUpdaterAtomicHelper is broken!", th);
        }
    }

    public final void d(C2631sv c2631sv) {
        c2631sv.a = null;
        while (true) {
            C2631sv c2631sv2 = this.c;
            if (c2631sv2 != C2631sv.c) {
                C2631sv c2631sv3 = null;
                while (c2631sv2 != null) {
                    C2631sv c2631sv4 = c2631sv2.b;
                    if (c2631sv2.a != null) {
                        c2631sv3 = c2631sv2;
                    } else if (c2631sv3 != null) {
                        c2631sv3.b = c2631sv4;
                        if (c2631sv3.a == null) {
                            break;
                        }
                    } else if (!g.A(this, c2631sv2, c2631sv4)) {
                        break;
                    }
                    c2631sv2 = c2631sv4;
                }
                return;
            }
            return;
        }
    }
}

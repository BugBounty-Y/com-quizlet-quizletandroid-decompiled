package com.google.android.gms.internal.ads;

import java.util.Set;
import java.util.logging.Level;

/* loaded from: classes2.dex */
public abstract class Dv extends AbstractC2417nv {
    public static final AbstractC1981ds j;
    public static final Wv k = new Wv(Dv.class, 0);
    public volatile Set h;
    public volatile int i;

    static {
        Throwable th;
        AbstractC1981ds cv;
        try {
            cv = new Bv();
            th = null;
        } catch (Throwable th2) {
            th = th2;
            cv = new Cv();
        }
        Throwable th3 = th;
        j = cv;
        if (th3 != null) {
            k.a().logp(Level.SEVERE, "com.google.common.util.concurrent.AggregateFutureState", "<clinit>", "SafeAtomicHelper is broken!", th3);
        }
    }
}

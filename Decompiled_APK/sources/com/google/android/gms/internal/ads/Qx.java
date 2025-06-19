package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Qx {
    public static final Qx b;
    public final HashMap a = new HashMap();

    static {
        Cw cw = new Cw(9);
        Qx qx = new Qx();
        try {
            qx.b(cw, Ox.class);
            b = qx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("unexpected error.", e);
        }
    }

    public final AbstractC2025es a(AbstractC2547qw abstractC2547qw, Integer num) {
        AbstractC2025es abstractC2025esA;
        synchronized (this) {
            Cw cw = (Cw) this.a.get(abstractC2547qw.getClass());
            if (cw == null) {
                throw new GeneralSecurityException("Cannot create a new key for parameters " + abstractC2547qw.toString() + ": no key creator for this class was registered.");
            }
            abstractC2025esA = cw.a(abstractC2547qw, num);
        }
        return abstractC2025esA;
    }

    public final synchronized void b(Cw cw, Class cls) {
        try {
            HashMap map = this.a;
            Cw cw2 = (Cw) map.get(cls);
            if (cw2 != null && !cw2.equals(cw)) {
                throw new GeneralSecurityException("Different key creator for parameters class " + cls.toString() + " already inserted");
            }
            map.put(cls, cw);
        } catch (Throwable th) {
            throw th;
        }
    }
}

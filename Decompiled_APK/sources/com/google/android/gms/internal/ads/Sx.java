package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Sx {
    public static final Sx b = new Sx();
    public final HashMap a = new HashMap();

    public final synchronized void a(Bw bw, Class cls) {
        try {
            HashMap map = this.a;
            Bw bw2 = (Bw) map.get(cls);
            if (bw2 != null && !bw2.equals(bw)) {
                throw new GeneralSecurityException("Different key creator for parameters class already inserted");
            }
            map.put(cls, bw);
        } catch (Throwable th) {
            throw th;
        }
    }
}

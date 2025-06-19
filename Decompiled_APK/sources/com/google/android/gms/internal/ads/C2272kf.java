package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.kf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2272kf {
    public final Map a;
    public final Map b;

    public /* synthetic */ C2272kf(Map map, Map map2) {
        this.a = map;
        this.b = map2;
    }

    public Enum a(Object obj) throws GeneralSecurityException {
        Enum r0 = (Enum) this.b.get(obj);
        if (r0 != null) {
            return r0;
        }
        throw new GeneralSecurityException("Unable to convert object enum: ".concat(String.valueOf(obj)));
    }

    public Object b(Enum r3) throws GeneralSecurityException {
        Object obj = this.a.get(r3);
        if (obj != null) {
            return obj;
        }
        throw new GeneralSecurityException("Unable to convert proto enum: ".concat(String.valueOf(r3)));
    }
}

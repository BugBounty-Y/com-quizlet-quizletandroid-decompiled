package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.z4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2899z4 extends AbstractC1972di {
    public String O;
    public final long P;
    public final String Q;
    public final String R;
    public final String S;

    public C2899z4(String str) {
        this.O = "E";
        this.P = -1L;
        this.Q = "E";
        this.R = "E";
        this.S = "E";
        HashMap mapC = AbstractC1972di.c(str);
        if (mapC != null) {
            this.O = mapC.get(0) == null ? "E" : (String) mapC.get(0);
            this.P = mapC.get(1) != null ? ((Long) mapC.get(1)).longValue() : -1L;
            this.Q = mapC.get(2) == null ? "E" : (String) mapC.get(2);
            this.R = mapC.get(3) == null ? "E" : (String) mapC.get(3);
            this.S = mapC.get(4) != null ? (String) mapC.get(4) : "E";
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1972di
    public final HashMap n() {
        HashMap map = new HashMap();
        map.put(0, this.O);
        map.put(4, this.S);
        map.put(3, this.R);
        map.put(2, this.Q);
        map.put(1, Long.valueOf(this.P));
        return map;
    }
}

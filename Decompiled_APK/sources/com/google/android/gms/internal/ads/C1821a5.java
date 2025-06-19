package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.a5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1821a5 extends AbstractC1972di {
    public final Long O;
    public final Long P;
    public final Long Q;
    public final Long R;
    public final Long S;
    public final Long T;
    public final Long U;
    public final Long V;
    public final Long W;
    public final Long X;
    public final Long Y;

    public C1821a5(String str) {
        HashMap mapC = AbstractC1972di.c(str);
        if (mapC != null) {
            this.O = (Long) mapC.get(0);
            this.P = (Long) mapC.get(1);
            this.Q = (Long) mapC.get(2);
            this.R = (Long) mapC.get(3);
            this.S = (Long) mapC.get(4);
            this.T = (Long) mapC.get(5);
            this.U = (Long) mapC.get(6);
            this.V = (Long) mapC.get(7);
            this.W = (Long) mapC.get(8);
            this.X = (Long) mapC.get(9);
            this.Y = (Long) mapC.get(10);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1972di
    public final HashMap n() {
        HashMap map = new HashMap();
        map.put(0, this.O);
        map.put(1, this.P);
        map.put(2, this.Q);
        map.put(3, this.R);
        map.put(4, this.S);
        map.put(5, this.T);
        map.put(6, this.U);
        map.put(7, this.V);
        map.put(8, this.W);
        map.put(9, this.X);
        map.put(10, this.Y);
        return map;
    }
}

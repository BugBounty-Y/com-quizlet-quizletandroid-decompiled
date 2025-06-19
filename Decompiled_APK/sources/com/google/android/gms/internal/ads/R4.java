package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* loaded from: classes2.dex */
public final class R4 extends AbstractC1972di {
    public final /* synthetic */ int O = 0;
    public Long P;
    public Object Q;
    public Object R;

    public /* synthetic */ R4() {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1972di
    public final HashMap n() {
        switch (this.O) {
            case 0:
                HashMap map = new HashMap();
                map.put(0, this.P);
                map.put(1, (Long) this.Q);
                map.put(2, (Long) this.R);
                return map;
            default:
                HashMap map2 = new HashMap();
                map2.put(0, this.P);
                map2.put(1, (Boolean) this.Q);
                map2.put(2, (Boolean) this.R);
                return map2;
        }
    }

    public R4(String str) {
        HashMap mapC = AbstractC1972di.c(str);
        if (mapC != null) {
            this.P = (Long) mapC.get(0);
            this.Q = (Boolean) mapC.get(1);
            this.R = (Boolean) mapC.get(2);
        }
    }
}

package com.google.android.gms.internal.ads;

import java.util.Map;

/* loaded from: classes2.dex */
public final class Ei implements InterfaceC2488pg {
    public final Map a;
    public final Map b;
    public final Map c;
    public final BC d;
    public final C1929cj e;

    public Ei(Map map, Map map2, Map map3, BC bc, C1929cj c1929cj) {
        this.a = map;
        this.b = map2;
        this.c = map3;
        this.d = bc;
        this.e = c1929cj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2488pg
    public final InterfaceC2751vm a(int i, String str) {
        InterfaceC2751vm interfaceC2751vmA;
        InterfaceC2751vm interfaceC2751vm = (InterfaceC2751vm) this.a.get(str);
        if (interfaceC2751vm != null) {
            return interfaceC2751vm;
        }
        if (i != 1) {
            if (i != 4) {
                return null;
            }
            Zm zm = (Zm) this.c.get(str);
            if (zm != null) {
                return new C2794wm(zm, new C2853y1(5));
            }
            interfaceC2751vmA = (InterfaceC2751vm) this.b.get(str);
            if (interfaceC2751vmA == null) {
                return null;
            }
        } else if (this.e.d == null || (interfaceC2751vmA = ((InterfaceC2488pg) this.d.zzb()).a(i, str)) == null) {
            return null;
        }
        return new C2794wm(interfaceC2751vmA, new C2853y1(6));
    }
}

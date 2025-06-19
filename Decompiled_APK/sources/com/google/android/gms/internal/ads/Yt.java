package com.google.android.gms.internal.ads;

import java.util.Map;

/* loaded from: classes2.dex */
public final class Yt extends St {
    public final Object a;
    public int b;
    public final /* synthetic */ Zt c;

    public Yt(Zt zt, int i) {
        this.c = zt;
        Object obj = Zt.j;
        this.a = zt.b()[i];
        this.b = i;
    }

    public final void a() {
        int i = this.b;
        Object obj = this.a;
        Zt zt = this.c;
        if (i != -1 && i < zt.size()) {
            if (AbstractC2457os.l(obj, zt.b()[this.b])) {
                return;
            }
        }
        Object obj2 = Zt.j;
        this.b = zt.j(obj);
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.a;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        Zt zt = this.c;
        Map mapE = zt.e();
        if (mapE != null) {
            return mapE.get(this.a);
        }
        a();
        int i = this.b;
        if (i == -1) {
            return null;
        }
        return zt.d()[i];
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        Zt zt = this.c;
        Map mapE = zt.e();
        Object obj2 = this.a;
        if (mapE != null) {
            return mapE.put(obj2, obj);
        }
        a();
        int i = this.b;
        if (i == -1) {
            zt.put(obj2, obj);
            return null;
        }
        Object obj3 = zt.d()[i];
        zt.d()[this.b] = obj;
        return obj3;
    }
}

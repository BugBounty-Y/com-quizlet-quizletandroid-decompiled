package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;

/* renamed from: com.google.android.gms.internal.ads.kl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2278kl {
    public final C1931cl a;
    public final C2620sk b;
    public final Object c = new Object();
    public final ArrayList d = new ArrayList();
    public boolean e;

    public C2278kl(C1931cl c1931cl, C2620sk c2620sk) {
        this.a = c1931cl;
        this.b = c2620sk;
    }

    public final JSONArray a() {
        JSONArray jSONArray = new JSONArray();
        synchronized (this.c) {
            try {
                if (!this.e) {
                    C1931cl c1931cl = this.a;
                    if (!c1931cl.b) {
                        com.google.android.gms.ads.internal.client.B0 b0 = new com.google.android.gms.ads.internal.client.B0(this, 1);
                        C1931cl c1931cl2 = this.a;
                        c1931cl2.getClass();
                        c1931cl2.e.a.a(new Qv(27, c1931cl2, b0), c1931cl2.j);
                        return jSONArray;
                    }
                    b(c1931cl.a());
                }
                Iterator it2 = this.d.iterator();
                while (it2.hasNext()) {
                    jSONArray.put(((C2235jl) it2.next()).a());
                }
                return jSONArray;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void b(List list) {
        zzbrz zzbrzVar;
        C2577rk c2577rkA;
        C2577rk c2577rkA2;
        zzbrz zzbrzVar2;
        synchronized (this.c) {
            try {
                if (this.e) {
                    return;
                }
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    zzblu zzbluVar = (zzblu) it2.next();
                    C2601s7 c2601s7 = AbstractC2773w7.q9;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    String string = (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || (c2577rkA2 = this.b.a(zzbluVar.a)) == null || (zzbrzVar2 = c2577rkA2.c) == null) ? "" : zzbrzVar2.toString();
                    String str = string;
                    boolean z = ((Boolean) rVar.c.a(AbstractC2773w7.r9)).booleanValue() && (c2577rkA = this.b.a(zzbluVar.a)) != null && c2577rkA.d;
                    ArrayList arrayList = this.d;
                    String str2 = zzbluVar.a;
                    C2577rk c2577rkA3 = this.b.a(str2);
                    arrayList.add(new C2235jl(str2, str, (c2577rkA3 == null || (zzbrzVar = c2577rkA3.b) == null) ? "" : zzbrzVar.toString(), zzbluVar.b ? 1 : 0, zzbluVar.d, zzbluVar.c, z));
                }
                this.e = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}

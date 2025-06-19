package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Map;
import java.util.concurrent.Executor;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ak, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1843ak {
    public final androidx.work.impl.model.c b;
    public final Context c;
    public final Hk d;
    public final Executor e;
    public final P4 f;
    public final VersionInfoParcel g;
    public final C2107gm i;
    public final C2584rr j;
    public final BinderC2408nm k;
    public final C2067fq l;
    public C2889yv m;
    public final Wj a = new Wj();
    public final C2217j9 h = new C2217j9();

    public C1843ak(Zj zj) {
        this.c = zj.b;
        this.e = zj.e;
        this.f = zj.f;
        this.g = zj.g;
        this.b = zj.a;
        this.i = zj.d;
        this.j = zj.h;
        this.d = zj.c;
        this.k = zj.i;
        this.l = zj.j;
    }

    public final synchronized com.google.common.util.concurrent.e a(String str, JSONObject jSONObject) {
        C2889yv c2889yv = this.m;
        if (c2889yv == null) {
            return Tv.b;
        }
        return AbstractC2025es.N(c2889yv, new C2616sg(this, str, jSONObject, 2), this.e);
    }

    public final synchronized void b(Map map) {
        C2889yv c2889yv = this.m;
        if (c2889yv == null) {
            return;
        }
        S4 s4 = new S4(map, 18);
        c2889yv.a(new Qv(0, c2889yv, s4), this.e);
    }

    public final synchronized void c(String str, InterfaceC2389n9 interfaceC2389n9) {
        C2889yv c2889yv = this.m;
        if (c2889yv == null) {
            return;
        }
        C1732Mb c1732Mb = new C1732Mb(21, str, interfaceC2389n9);
        c2889yv.a(new Qv(0, c2889yv, c1732Mb), this.e);
    }

    public final synchronized void d(String str, InterfaceC2389n9 interfaceC2389n9) {
        C2889yv c2889yv = this.m;
        if (c2889yv == null) {
            return;
        }
        Fi fi = new Fi(18, str, interfaceC2389n9);
        c2889yv.a(new Qv(0, c2889yv, fi), this.e);
    }
}

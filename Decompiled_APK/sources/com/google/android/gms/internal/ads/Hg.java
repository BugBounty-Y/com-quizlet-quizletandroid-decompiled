package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class Hg implements Jh, InterfaceC2618si {
    public final Context a;
    public final C2023eq b;
    public final VersionInfoParcel c;
    public final com.google.android.gms.ads.internal.util.C d;
    public final C1931cl e;
    public final Uq f;
    public final C2493pl g;

    public Hg(Context context, C2023eq c2023eq, VersionInfoParcel versionInfoParcel, com.google.android.gms.ads.internal.util.C c, C1931cl c1931cl, Uq uq, C2493pl c2493pl) {
        this.a = context;
        this.b = c2023eq;
        this.c = versionInfoParcel;
        this.d = c;
        this.e = c1931cl;
        this.f = uq;
        this.g = c2493pl;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(com.google.android.gms.ads.nonagon.signalgeneration.q qVar) throws JSONException {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.d4)).booleanValue()) {
            c();
        }
    }

    public final void c() throws JSONException {
        String str;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c4)).booleanValue()) {
            C2023eq c2023eq = this.b;
            C1923cd c1923cdN = this.d.n();
            androidx.compose.foundation.gestures.l1 l1Var = com.google.android.gms.ads.internal.j.C.l;
            boolean zF = this.g.f();
            if (c1923cdN != null) {
                l1Var.getClass();
                str = c1923cdN.d;
            } else {
                str = null;
            }
            l1Var.I(this.a, this.c, false, c1923cdN, str, c2023eq.f, null, this.f, null, null, zF);
        }
        this.e.b();
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) throws JSONException {
        c();
    }
}

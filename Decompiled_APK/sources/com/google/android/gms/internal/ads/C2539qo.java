package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.qo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2539qo implements Uo {
    public final Context a;
    public final Bundle b;
    public final String c;
    public final String d;
    public final com.google.android.gms.ads.internal.util.C e;
    public final String f;
    public final Dg g;

    public C2539qo(Context context, Bundle bundle, String str, String str2, com.google.android.gms.ads.internal.util.C c, String str3, Dg dg) {
        this.a = context;
        this.b = bundle;
        this.c = str;
        this.d = str2;
        this.e = c;
        this.f = str3;
        this.g = dg;
    }

    public final void a(Bundle bundle) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F5)).booleanValue()) {
            try {
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                bundle.putString("_app_id", com.google.android.gms.ads.internal.util.F.G(this.a));
            } catch (RemoteException | RuntimeException e) {
                com.google.android.gms.ads.internal.j.C.h.h("AppStatsSignal_AppId", e);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        Bundle bundle = ((Og) obj).b;
        bundle.putBundle("quality_signals", this.b);
        a(bundle);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        bundle.putBundle("quality_signals", this.b);
        bundle.putString("seq_num", this.c);
        if (!this.e.k()) {
            bundle.putString("session_id", this.d);
        }
        bundle.putBoolean("client_purpose_one", !r0.k());
        a(bundle);
        String str = this.f;
        if (str != null) {
            Bundle bundle2 = new Bundle();
            Dg dg = this.g;
            Long l = (Long) dg.d.get(str);
            bundle2.putLong("dload", l == null ? -1L : l.longValue());
            Integer num = (Integer) dg.b.get(str);
            bundle2.putInt("pcc", num == null ? 0 : num.intValue());
            bundle.putBundle("ad_unit_quality_signals", bundle2);
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L9)).booleanValue()) {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            if (jVar.h.k.get() > 0) {
                bundle.putInt("nrwv", jVar.h.k.get());
            }
        }
    }
}

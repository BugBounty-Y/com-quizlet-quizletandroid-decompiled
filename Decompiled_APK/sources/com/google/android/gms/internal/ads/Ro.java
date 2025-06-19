package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class Ro implements Uo {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final Long e;

    public Ro(String str, String str2, String str3, String str4, Long l) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        this.e = l;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        AbstractC2096gb.t("fbs_aeid", this.c, ((Og) obj).b);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        AbstractC2096gb.t("gmp_app_id", this.a, bundle);
        AbstractC2096gb.t("fbs_aiid", this.b, bundle);
        AbstractC2096gb.t("fbs_aeid", this.c, bundle);
        AbstractC2096gb.t("apm_id_origin", this.d, bundle);
        Long l = this.e;
        if (l != null) {
            bundle.putLong("sai_timeout", l.longValue());
        }
    }
}

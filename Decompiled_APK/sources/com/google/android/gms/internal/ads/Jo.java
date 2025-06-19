package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class Jo implements Uo {
    public final String a;
    public final Integer b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;

    public Jo(String str, Integer num, String str2, String str3, String str4, String str5) {
        this.a = str;
        this.b = num;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        Bundle bundle = ((Og) obj).b;
        AbstractC2096gb.t("pn", this.a, bundle);
        AbstractC2096gb.t("dl", this.d, bundle);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        AbstractC2096gb.t("pn", this.a, bundle);
        Integer num = this.b;
        if (num != null) {
            bundle.putInt("vc", num.intValue());
        }
        AbstractC2096gb.t("vnm", this.c, bundle);
        AbstractC2096gb.t("dl", this.d, bundle);
        AbstractC2096gb.t("ins_pn", this.e, bundle);
        AbstractC2096gb.t("ini_pn", this.f, bundle);
    }
}

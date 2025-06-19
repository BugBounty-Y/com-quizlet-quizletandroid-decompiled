package com.google.android.gms.internal.ads;

import android.graphics.Insets;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.text.TextUtils;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.onetrust.otpublishers.headless.Public.OTBannerHeightRatio;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.fo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2065fo implements Uo {
    public final com.google.android.gms.ads.internal.client.zzr a;
    public final String b;
    public final boolean c;
    public final String d;
    public final float e;
    public final int f;
    public final int g;
    public final String h;
    public final boolean i;
    public final Insets j;

    public C2065fo(com.google.android.gms.ads.internal.client.zzr zzrVar, String str, boolean z, String str2, float f, int i, int i2, String str3, boolean z2, Insets insets) {
        com.google.android.gms.common.internal.u.i(zzrVar, "the adSize must not be null");
        this.a = zzrVar;
        this.b = str;
        this.c = z;
        this.d = str2;
        this.e = f;
        this.f = i;
        this.g = i2;
        this.h = str3;
        this.i = z2;
        this.j = insets;
    }

    public final void a(Bundle bundle) {
        Insets insets;
        com.google.android.gms.ads.internal.client.zzr zzrVar = this.a;
        int i = zzrVar.e;
        AbstractC2096gb.I(bundle, "smart_w", OTBannerHeightRatio.FULL, i == -1);
        int i2 = zzrVar.b;
        AbstractC2096gb.I(bundle, "smart_h", "auto", i2 == -2);
        AbstractC2096gb.K(bundle, "ene", true, zzrVar.j);
        AbstractC2096gb.I(bundle, "rafmt", "102", zzrVar.m);
        AbstractC2096gb.I(bundle, "rafmt", "103", zzrVar.n);
        boolean z = zzrVar.o;
        AbstractC2096gb.I(bundle, "rafmt", "105", z);
        AbstractC2096gb.K(bundle, "inline_adaptive_slot", true, this.i);
        AbstractC2096gb.K(bundle, "interscroller_slot", true, z);
        AbstractC2096gb.t("format", this.b, bundle);
        AbstractC2096gb.I(bundle, "fluid", OTUXParamsKeys.OT_UX_HEIGHT, this.c);
        AbstractC2096gb.I(bundle, "sz", this.d, !TextUtils.isEmpty(r2));
        bundle.putFloat("u_sd", this.e);
        bundle.putInt("sw", this.f);
        bundle.putInt("sh", this.g);
        String str = this.h;
        AbstractC2096gb.I(bundle, "sc", str, true ^ TextUtils.isEmpty(str));
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.jd)).booleanValue() && Build.VERSION.SDK_INT >= 35 && (insets = this.j) != null) {
            bundle.putInt("sam_t", insets.top);
            bundle.putInt("sam_b", insets.bottom);
            bundle.putInt("sam_l", insets.left);
            bundle.putInt("sam_r", insets.right);
        }
        ArrayList<? extends Parcelable> arrayList = new ArrayList<>();
        com.google.android.gms.ads.internal.client.zzr[] zzrVarArr = zzrVar.g;
        if (zzrVarArr == null) {
            Bundle bundle2 = new Bundle();
            bundle2.putInt(OTUXParamsKeys.OT_UX_HEIGHT, i2);
            bundle2.putInt(OTUXParamsKeys.OT_UX_WIDTH, i);
            bundle2.putBoolean("is_fluid_height", zzrVar.i);
            arrayList.add(bundle2);
        } else {
            for (com.google.android.gms.ads.internal.client.zzr zzrVar2 : zzrVarArr) {
                Bundle bundle3 = new Bundle();
                bundle3.putBoolean("is_fluid_height", zzrVar2.i);
                bundle3.putInt(OTUXParamsKeys.OT_UX_HEIGHT, zzrVar2.b);
                bundle3.putInt(OTUXParamsKeys.OT_UX_WIDTH, zzrVar2.e);
                arrayList.add(bundle3);
            }
        }
        bundle.putParcelableArrayList("valid_ad_sizes", arrayList);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        a(((Og) obj).b);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void c(Object obj) {
        a(((Og) obj).a);
    }
}

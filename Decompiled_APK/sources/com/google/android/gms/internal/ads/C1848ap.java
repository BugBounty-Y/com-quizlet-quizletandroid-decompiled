package com.google.android.gms.internal.ads;

import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.ap, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1848ap implements Uo {
    public final boolean a;
    public final boolean b;
    public final String c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final String g;
    public final String h;
    public final ArrayList i;
    public final String j;
    public final String k;
    public final boolean l;
    public final long m;
    public final boolean n;
    public final String o;
    public final int p;

    public C1848ap(boolean z, boolean z2, String str, boolean z3, boolean z4, boolean z5, String str2, ArrayList arrayList, String str3, String str4, boolean z6, long j, boolean z7, String str5, int i, String str6) {
        String str7 = Build.FINGERPRINT;
        String str8 = Build.MODEL;
        this.a = z;
        this.b = z2;
        this.c = str;
        this.d = z3;
        this.e = z4;
        this.f = z5;
        this.g = str2;
        this.h = str6;
        this.i = arrayList;
        this.j = str3;
        this.k = str4;
        this.l = z6;
        this.m = j;
        this.n = z7;
        this.o = str5;
        this.p = i;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        Bundle bundle = ((Og) obj).b;
        bundle.putBoolean("simulator", this.d);
        bundle.putInt("build_api_level", this.p);
        ArrayList<String> arrayList = this.i;
        if (!arrayList.isEmpty()) {
            bundle.putStringArrayList("hl_list", arrayList);
        }
        bundle.putString("submodel", Build.MODEL);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        bundle.putBoolean("cog", this.a);
        bundle.putBoolean("coh", this.b);
        bundle.putString("gl", this.c);
        bundle.putBoolean("simulator", this.d);
        bundle.putBoolean("is_latchsky", this.e);
        bundle.putInt("build_api_level", this.p);
        C2601s7 c2601s7 = AbstractC2773w7.ab;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            bundle.putBoolean("is_sidewinder", this.f);
        }
        bundle.putString("hl", this.g);
        C2601s7 c2601s72 = AbstractC2773w7.kd;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
            bundle.putString("dlc", this.h);
        }
        ArrayList<String> arrayList = this.i;
        if (!arrayList.isEmpty()) {
            bundle.putStringArrayList("hl_list", arrayList);
        }
        bundle.putString("mv", this.j);
        bundle.putString("submodel", Build.MODEL);
        Bundle bundleD = AbstractC2096gb.d(bundle, "device");
        bundle.putBundle("device", bundleD);
        bundleD.putString("build", Build.FINGERPRINT);
        bundleD.putLong("remaining_data_partition_space", this.m);
        Bundle bundleD2 = AbstractC2096gb.d(bundleD, "browser");
        bundleD.putBundle("browser", bundleD2);
        bundleD2.putBoolean("is_browser_custom_tabs_capable", this.l);
        String str = this.k;
        if (!TextUtils.isEmpty(str)) {
            Bundle bundleD3 = AbstractC2096gb.d(bundleD, "play_store");
            bundleD.putBundle("play_store", bundleD3);
            bundleD3.putString("package_version", str);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.qb)).booleanValue()) {
            bundle.putBoolean("is_bstar", this.n);
        }
        String str2 = this.o;
        if (!TextUtils.isEmpty(str2)) {
            bundle.putString("v_unity", str2);
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.kb)).booleanValue()) {
            AbstractC2096gb.K(bundle, "gotmt_l", true, ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.hb)).booleanValue());
            AbstractC2096gb.K(bundle, "gotmt_i", true, ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.gb)).booleanValue());
        }
    }
}

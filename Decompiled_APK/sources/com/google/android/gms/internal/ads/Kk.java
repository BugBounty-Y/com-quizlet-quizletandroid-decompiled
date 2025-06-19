package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Kk {
    public final HashMap a;
    public final Context b;
    public final Xv c;
    public final com.google.android.gms.ads.internal.util.client.k d;
    public final boolean e;
    public final com.google.android.gms.ads.nonagon.util.logging.csi.a f;
    public final boolean g;
    public final boolean h;
    public final AtomicBoolean i;
    public final AtomicReference j;

    public Kk(Xv xv, com.google.android.gms.ads.internal.util.client.k kVar, com.quizlet.data.repository.classfolder.e eVar, com.google.android.gms.ads.nonagon.util.logging.csi.a aVar, Context context) {
        HashMap map = new HashMap();
        this.a = map;
        this.i = new AtomicBoolean();
        this.j = new AtomicReference(new Bundle());
        this.c = xv;
        this.d = kVar;
        C2601s7 c2601s7 = AbstractC2773w7.a2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.e = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        this.f = aVar;
        C2601s7 c2601s72 = AbstractC2773w7.f2;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        this.g = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue();
        this.h = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.S6)).booleanValue();
        this.b = context;
        map.put("s", "gmob_sdk");
        map.put("v", "3");
        map.put("os", Build.VERSION.RELEASE);
        map.put("api_v", Build.VERSION.SDK);
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.F f = jVar.c;
        map.put("device", com.google.android.gms.ads.internal.util.F.I());
        map.put("app", (String) eVar.c);
        Context context2 = (Context) eVar.b;
        map.put("is_lite_sdk", true != com.google.android.gms.ads.internal.util.F.e(context2) ? "0" : "1");
        ArrayList arrayListO = rVar.a.o();
        boolean zBooleanValue = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.N6)).booleanValue();
        C2010ed c2010ed = jVar.h;
        if (zBooleanValue) {
            arrayListO.addAll(c2010ed.d().n().i);
        }
        map.put("e", TextUtils.join(",", arrayListO));
        map.put("sdkVersion", (String) eVar.d);
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.pb)).booleanValue()) {
            map.put("is_bstar", true != com.google.android.gms.ads.internal.util.F.c(context2) ? "0" : "1");
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.u9)).booleanValue() && ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.t2)).booleanValue()) {
            String str = c2010ed.g;
            map.put("plugin", str == null ? "" : str);
        }
    }

    public final void a(Map map) {
        Bundle bundleD;
        if (map == null || map.isEmpty()) {
            com.google.android.gms.ads.internal.util.client.i.d("Empty or null paramMap.");
            return;
        }
        boolean andSet = this.i.getAndSet(true);
        AtomicReference atomicReference = this.j;
        if (!andSet) {
            String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.za);
            SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc = new SharedPreferencesOnSharedPreferenceChangeListenerC1751Pc(str, 1, this);
            if (TextUtils.isEmpty(str)) {
                bundleD = Bundle.EMPTY;
            } else {
                Context context = this.b;
                PreferenceManager.getDefaultSharedPreferences(context).registerOnSharedPreferenceChangeListener(sharedPreferencesOnSharedPreferenceChangeListenerC1751Pc);
                bundleD = com.google.android.gms.internal.mlkit_vision_common.U2.d(context, str);
            }
            atomicReference.set(bundleD);
        }
        Bundle bundle = (Bundle) atomicReference.get();
        for (String str2 : bundle.keySet()) {
            map.put(str2, String.valueOf(bundle.get(str2)));
        }
    }

    public final void b(Map map, boolean z) {
        if (map.isEmpty()) {
            com.google.android.gms.ads.internal.util.client.i.d("Empty paramMap.");
            return;
        }
        a(map);
        String strA = this.f.a(map);
        com.google.android.gms.ads.internal.util.A.l(strA);
        boolean z2 = Boolean.parseBoolean((String) map.get("scar"));
        if (this.e) {
            if (!z || this.g) {
                if (!z2 || this.h) {
                    this.c.execute(new Lk(this, strA, 0));
                }
            }
        }
    }
}

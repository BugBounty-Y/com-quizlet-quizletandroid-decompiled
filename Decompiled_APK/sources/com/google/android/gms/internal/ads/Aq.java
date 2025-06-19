package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class Aq {
    public final HashMap a = new HashMap();

    public final C2927zq a(EnumC2712uq enumC2712uq, Context context, C2498pq c2498pq, Os os) {
        zzfej zzfejVar;
        HashMap map = this.a;
        C2927zq c2927zq = (C2927zq) map.get(enumC2712uq);
        if (c2927zq != null) {
            return c2927zq;
        }
        if (enumC2712uq == EnumC2712uq.a) {
            C2601s7 c2601s7 = AbstractC2773w7.n6;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            int iIntValue = ((Integer) rVar.c.a(c2601s7)).intValue();
            C2601s7 c2601s72 = AbstractC2773w7.t6;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            zzfejVar = new zzfej(context, enumC2712uq, iIntValue, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue(), ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.v6)).intValue(), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.x6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.p6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.r6));
        } else if (enumC2712uq == EnumC2712uq.b) {
            C2601s7 c2601s73 = AbstractC2773w7.o6;
            com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
            int iIntValue2 = ((Integer) rVar2.c.a(c2601s73)).intValue();
            C2601s7 c2601s74 = AbstractC2773w7.u6;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u72 = rVar2.c;
            zzfejVar = new zzfej(context, enumC2712uq, iIntValue2, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(c2601s74)).intValue(), ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.w6)).intValue(), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.y6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.q6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.s6));
        } else if (enumC2712uq == EnumC2712uq.c) {
            C2601s7 c2601s75 = AbstractC2773w7.B6;
            com.google.android.gms.ads.internal.client.r rVar3 = com.google.android.gms.ads.internal.client.r.d;
            int iIntValue3 = ((Integer) rVar3.c.a(c2601s75)).intValue();
            C2601s7 c2601s76 = AbstractC2773w7.D6;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u73 = rVar3.c;
            zzfejVar = new zzfej(context, enumC2712uq, iIntValue3, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(c2601s76)).intValue(), ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(AbstractC2773w7.E6)).intValue(), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(AbstractC2773w7.z6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(AbstractC2773w7.A6), (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u73.a(AbstractC2773w7.C6));
        } else {
            zzfejVar = null;
        }
        C2326lq c2326lq = new C2326lq(zzfejVar);
        C2927zq c2927zq2 = new C2927zq(c2326lq, new YF(c2326lq, c2498pq, os));
        map.put(enumC2712uq, c2927zq2);
        return c2927zq2;
    }
}

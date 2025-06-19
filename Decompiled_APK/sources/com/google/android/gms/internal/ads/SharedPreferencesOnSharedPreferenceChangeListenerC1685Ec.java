package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

/* renamed from: com.google.android.gms.internal.ads.Ec, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec implements SharedPreferences.OnSharedPreferenceChangeListener {
    public final Context a;
    public final SharedPreferences b;
    public final com.google.android.gms.ads.internal.util.C c;
    public String d = "-1";
    public int e = -1;

    public SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec(Context context, com.google.android.gms.ads.internal.util.C c) {
        this.b = PreferenceManager.getDefaultSharedPreferences(context);
        this.c = c;
        this.a = context;
    }

    public final void a(int i, String str) {
        Context context;
        C2601s7 c2601s7 = AbstractC2773w7.E0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean z = true;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() ? !(str.isEmpty() || str.charAt(0) != '1') : !(i == 0 || str.isEmpty() || (str.charAt(0) != '1' && !str.equals("-1")))) {
            z = false;
        }
        this.c.c(z);
        if (((Boolean) rVar.c.a(AbstractC2773w7.g6)).booleanValue() && z && (context = this.a) != null) {
            context.deleteDatabase("OfflineUpload.db");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0088  */
    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onSharedPreferenceChanged(android.content.SharedPreferences r10, java.lang.String r11) {
        /*
            r9 = this;
            java.lang.String r0 = "IABTCF_PurposeConsents"
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.G0     // Catch: java.lang.Throwable -> L39
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L39
            com.google.android.gms.internal.ads.u7 r3 = r2.c     // Catch: java.lang.Throwable -> L39
            java.lang.Object r1 = r3.a(r1)     // Catch: java.lang.Throwable -> L39
            java.lang.Boolean r1 = (java.lang.Boolean) r1     // Catch: java.lang.Throwable -> L39
            boolean r1 = r1.booleanValue()     // Catch: java.lang.Throwable -> L39
            r3 = 1
            java.lang.String r4 = "-1"
            r5 = -1
            java.lang.String r6 = "gad_has_consent_for_cookies"
            if (r1 == 0) goto L5d
            boolean r0 = java.util.Objects.equals(r11, r6)     // Catch: java.lang.Throwable -> L39
            android.content.Context r1 = r9.a
            com.google.android.gms.ads.internal.util.C r2 = r9.c
            if (r0 == 0) goto L3c
            int r10 = r10.getInt(r6, r5)     // Catch: java.lang.Throwable -> L39
            r2.l()     // Catch: java.lang.Throwable -> L39
            int r11 = r2.m     // Catch: java.lang.Throwable -> L39
            if (r10 == r11) goto L35
            r2.c(r3)     // Catch: java.lang.Throwable -> L39
            com.google.android.gms.internal.mlkit_vision_common.U2.e(r1)     // Catch: java.lang.Throwable -> L39
        L35:
            r2.a(r10)     // Catch: java.lang.Throwable -> L39
            return
        L39:
            r10 = move-exception
            goto Lbe
        L3c:
            java.lang.String r0 = "IABTCF_TCString"
            boolean r0 = java.util.Objects.equals(r11, r0)     // Catch: java.lang.Throwable -> L39
            if (r0 == 0) goto Lca
            java.lang.String r10 = r10.getString(r11, r4)     // Catch: java.lang.Throwable -> L39
            r2.l()     // Catch: java.lang.Throwable -> L39
            java.lang.String r11 = r2.l     // Catch: java.lang.Throwable -> L39
            boolean r11 = java.util.Objects.equals(r10, r11)     // Catch: java.lang.Throwable -> L39
            if (r11 != 0) goto L59
            r2.c(r3)     // Catch: java.lang.Throwable -> L39
            com.google.android.gms.internal.mlkit_vision_common.U2.e(r1)     // Catch: java.lang.Throwable -> L39
        L59:
            r2.h(r10)     // Catch: java.lang.Throwable -> L39
            return
        L5d:
            java.lang.String r1 = r10.getString(r0, r4)     // Catch: java.lang.Throwable -> L39
            int r10 = r10.getInt(r6, r5)     // Catch: java.lang.Throwable -> L39
            java.lang.String r11 = java.lang.String.valueOf(r11)     // Catch: java.lang.Throwable -> L39
            int r7 = r11.hashCode()     // Catch: java.lang.Throwable -> L39
            r8 = -2004976699(0xffffffff887e7bc5, float:-7.6580835E-34)
            if (r7 == r8) goto L80
            r0 = -527267622(0xffffffffe09288da, float:-8.447143E19)
            if (r7 == r0) goto L78
            goto L88
        L78:
            boolean r11 = r11.equals(r6)
            if (r11 == 0) goto L88
            r11 = r3
            goto L89
        L80:
            boolean r11 = r11.equals(r0)
            if (r11 == 0) goto L88
            r11 = 0
            goto L89
        L88:
            r11 = r5
        L89:
            if (r11 == 0) goto Laa
            if (r11 == r3) goto L8e
            goto Lca
        L8e:
            com.google.android.gms.internal.ads.s7 r11 = com.google.android.gms.internal.ads.AbstractC2773w7.E0     // Catch: java.lang.Throwable -> L39
            com.google.android.gms.internal.ads.u7 r0 = r2.c     // Catch: java.lang.Throwable -> L39
            java.lang.Object r11 = r0.a(r11)     // Catch: java.lang.Throwable -> L39
            java.lang.Boolean r11 = (java.lang.Boolean) r11     // Catch: java.lang.Throwable -> L39
            boolean r11 = r11.booleanValue()     // Catch: java.lang.Throwable -> L39
            if (r11 == 0) goto Lca
            if (r10 == r5) goto Lca
            int r11 = r9.e     // Catch: java.lang.Throwable -> L39
            if (r11 == r10) goto Lca
            r9.e = r10     // Catch: java.lang.Throwable -> L39
            r9.a(r10, r1)     // Catch: java.lang.Throwable -> L39
            return
        Laa:
            boolean r11 = r1.equals(r4)     // Catch: java.lang.Throwable -> L39
            if (r11 != 0) goto Lca
            java.lang.String r11 = r9.d     // Catch: java.lang.Throwable -> L39
            boolean r11 = r11.equals(r1)     // Catch: java.lang.Throwable -> L39
            if (r11 != 0) goto Lca
            r9.d = r1     // Catch: java.lang.Throwable -> L39
            r9.a(r10, r1)     // Catch: java.lang.Throwable -> L39
            return
        Lbe:
            com.google.android.gms.ads.internal.j r11 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.internal.ads.ed r11 = r11.h
            java.lang.String r0 = "AdMobPlusIdlessListener.onSharedPreferenceChanged"
            r11.h(r0, r10)
            com.google.android.gms.ads.internal.util.A.m()
        Lca:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec.onSharedPreferenceChanged(android.content.SharedPreferences, java.lang.String):void");
    }
}

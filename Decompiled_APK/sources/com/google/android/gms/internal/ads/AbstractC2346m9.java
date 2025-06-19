package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.m9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2346m9 {
    public static final C2175i9 a = new C2175i9(0);
    public static final C2175i9 b = new C2175i9(1);
    public static final C2175i9 c = new C2175i9(3);
    public static final C2175i9 d = new C2175i9(17);
    public static final C2175i9 e = new C2175i9(18);
    public static final C2175i9 f = new C2175i9(4);
    public static final C2175i9 g = new C2175i9(19);
    public static final C2175i9 h = new C2175i9(20);
    public static final C2175i9 i = new C2175i9(2);
    public static final C2175i9 j = new C2175i9(21);
    public static final C2175i9 k = new C2175i9(22);
    public static final C1734Md l = new C1734Md();
    public static final C2175i9 m = new C2175i9(25);
    public static final C2087g9 n = new C2087g9();
    public static final C2217j9 o = new C2217j9();
    public static final C2175i9 p = new C2175i9(23);
    public static final C2175i9 q = new C2175i9(24);
    public static final C2175i9 r = new C2175i9(5);
    public static final C2175i9 s = new C2175i9(6);
    public static final C2175i9 t = new C2175i9(7);
    public static final C2175i9 u = new C2175i9(8);
    public static final C2175i9 v = new C2175i9(9);
    public static final C2175i9 w = new C2175i9(10);
    public static final C2175i9 x = new C2175i9(11);
    public static final C2175i9 y = new C2175i9(12);
    public static final C2175i9 z = new C2175i9(13);
    public static final C2175i9 A = new C2175i9(14);
    public static final C2175i9 B = new C2175i9(15);
    public static final C2175i9 C = new C2175i9(16);

    public static com.google.common.util.concurrent.e a(InterfaceC2529qe interfaceC2529qe, String str) {
        C1739Nc c1739Nc;
        String strA;
        String strReplace;
        Uri uriA = Uri.parse(str);
        try {
            P4 p4H0 = interfaceC2529qe.h0();
            C2067fq c2067fqA0 = interfaceC2529qe.A0();
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Xb)).booleanValue() || c2067fqA0 == null) {
                if (p4H0 != null && p4H0.c(uriA)) {
                    uriA = p4H0.a(uriA, interfaceC2529qe.getContext(), interfaceC2529qe.N(), interfaceC2529qe.zzi());
                }
            } else if (p4H0 != null && p4H0.c(uriA)) {
                uriA = c2067fqA0.a(uriA, interfaceC2529qe.getContext(), interfaceC2529qe.N(), interfaceC2529qe.zzi());
            }
        } catch (zzavm unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Unable to append parameter to URL: ".concat(str));
        }
        HashMap map = new HashMap();
        if (interfaceC2529qe.e() != null) {
            map = interfaceC2529qe.e().w0;
        }
        Context context = interfaceC2529qe.getContext();
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        if (jVar.y.e(context) && (strA = (c1739Nc = jVar.y).a(context)) != null) {
            C2601s7 c2601s7 = AbstractC2773w7.n0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            String str2 = (String) rVar.c.a(c2601s7);
            String string = uriA.toString();
            C2601s7 c2601s72 = AbstractC2773w7.m0;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() && string.contains(str2)) {
                c1739Nc.k(context, "_ac", strA, C1739Nc.f((Map) map.get("_ac")));
                strReplace = AbstractC1795We.A(context, string).replace(str2, strA);
            } else if (!TextUtils.isEmpty(uriA.getQueryParameter("fbs_aeid")) || ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.l0)).booleanValue()) {
                strReplace = string;
            } else {
                String string2 = AbstractC1795We.d(AbstractC1795We.A(context, string), "fbs_aeid", strA).toString();
                c1739Nc.k(context, "_ac", strA, C1739Nc.f((Map) map.get("_ac")));
                strReplace = string2;
            }
        } else {
            strReplace = uriA.toString();
        }
        long jLongValue = ((Long) V7.e.o()).longValue();
        if (jLongValue <= 0 || jLongValue > 251815200) {
            return AbstractC2025es.E(strReplace);
        }
        Nv nvT = Nv.t(interfaceC2529qe.b0());
        C2853y1 c2853y1 = new C2853y1(2);
        C2227jd c2227jd = AbstractC2270kd.g;
        return AbstractC2025es.x(AbstractC2025es.L(AbstractC2025es.x(nvT, Throwable.class, c2853y1, c2227jd), new C2131h9(strReplace, 0), c2227jd), Throwable.class, new C2131h9(strReplace, 1), c2227jd);
    }

    public static void b(Map map, InterfaceC2447oi interfaceC2447oi) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ka)).booleanValue() && map.containsKey("sc") && ((String) map.get("sc")).equals("1") && interfaceC2447oi != null) {
            interfaceC2447oi.c0();
        }
    }
}

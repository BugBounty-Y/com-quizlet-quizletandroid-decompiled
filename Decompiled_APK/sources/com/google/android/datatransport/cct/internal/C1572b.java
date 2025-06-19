package com.google.android.datatransport.cct.internal;

import com.amazon.device.ads.DtbDeviceData;
import com.appsflyer.AdRevenueScheme;

/* renamed from: com.google.android.datatransport.cct.internal.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1572b implements com.google.firebase.encoders.c {
    public static final C1572b a = new C1572b();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("sdkVersion");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b(DtbDeviceData.DEVICE_DATA_MODEL_KEY);
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("hardware");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("device");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("product");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("osBuild");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("manufacturer");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("fingerprint");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("locale");
    public static final com.google.firebase.encoders.b k = com.google.firebase.encoders.b.b(AdRevenueScheme.COUNTRY);
    public static final com.google.firebase.encoders.b l = com.google.firebase.encoders.b.b("mccMnc");
    public static final com.google.firebase.encoders.b m = com.google.firebase.encoders.b.b("applicationBuild");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        l lVar = (l) ((AbstractC1571a) obj);
        dVar.g(b, lVar.a);
        dVar.g(c, lVar.b);
        dVar.g(d, lVar.c);
        dVar.g(e, lVar.d);
        dVar.g(f, lVar.e);
        dVar.g(g, lVar.f);
        dVar.g(h, lVar.g);
        dVar.g(i, lVar.h);
        dVar.g(j, lVar.i);
        dVar.g(k, lVar.j);
        dVar.g(l, lVar.k);
        dVar.g(m, lVar.l);
    }
}

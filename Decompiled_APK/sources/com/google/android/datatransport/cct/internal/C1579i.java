package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1579i implements com.google.firebase.encoders.c {
    public static final C1579i a = new C1579i();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("eventTimeMs");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("eventCode");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("complianceData");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("eventUptimeMs");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("sourceExtension");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("sourceExtensionJsonProto3");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("timezoneOffsetSeconds");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("networkConnectionInfo");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("experimentIds");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        t tVar = (t) ((F) obj);
        dVar.b(b, tVar.a);
        dVar.g(c, tVar.b);
        dVar.g(d, tVar.c);
        dVar.b(e, tVar.d);
        dVar.g(f, tVar.e);
        dVar.g(g, tVar.f);
        dVar.b(h, tVar.g);
        dVar.g(i, tVar.h);
        dVar.g(j, tVar.i);
    }
}

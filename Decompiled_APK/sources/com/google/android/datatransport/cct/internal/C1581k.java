package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1581k implements com.google.firebase.encoders.c {
    public static final C1581k a = new C1581k();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("networkType");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("mobileSubtype");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        w wVar = (w) ((J) obj);
        dVar.g(b, wVar.a);
        dVar.g(c, wVar.b);
    }
}

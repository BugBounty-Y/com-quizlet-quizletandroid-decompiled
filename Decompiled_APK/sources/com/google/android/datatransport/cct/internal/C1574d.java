package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1574d implements com.google.firebase.encoders.c {
    public static final C1574d a = new C1574d();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("clientType");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("androidClientInfo");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        n nVar = (n) ((z) obj);
        nVar.getClass();
        dVar.g(b, y.a);
        dVar.g(c, nVar.a);
    }
}

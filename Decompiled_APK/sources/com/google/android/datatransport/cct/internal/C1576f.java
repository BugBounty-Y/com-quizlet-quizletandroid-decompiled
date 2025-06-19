package com.google.android.datatransport.cct.internal;

/* renamed from: com.google.android.datatransport.cct.internal.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1576f implements com.google.firebase.encoders.c {
    public static final C1576f a = new C1576f();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("clearBlob");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("encryptedBlob");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        p pVar = (p) ((C) obj);
        dVar.g(b, pVar.a);
        dVar.g(c, pVar.b);
    }
}

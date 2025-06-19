package com.google.android.datatransport.runtime;

/* loaded from: classes2.dex */
public final class g implements com.google.firebase.encoders.c {
    public static final g a = new g();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("startMs", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("endMs", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(2))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.android.datatransport.runtime.firebase.transport.g gVar = (com.google.android.datatransport.runtime.firebase.transport.g) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.b(b, gVar.a);
        dVar.b(c, gVar.b);
    }
}

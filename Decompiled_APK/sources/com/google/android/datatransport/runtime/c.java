package com.google.android.datatransport.runtime;

/* loaded from: classes2.dex */
public final class c implements com.google.firebase.encoders.c {
    public static final c a = new c();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("eventsDroppedCount", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("reason", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(3))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.android.datatransport.runtime.firebase.transport.d dVar = (com.google.android.datatransport.runtime.firebase.transport.d) obj;
        com.google.firebase.encoders.d dVar2 = (com.google.firebase.encoders.d) obj2;
        dVar2.b(b, dVar.a);
        dVar2.g(c, dVar.b);
    }
}

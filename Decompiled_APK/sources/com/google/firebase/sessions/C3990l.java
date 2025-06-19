package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3990l {
    public final com.google.firebase.inject.b a;

    public C3990l(com.google.firebase.inject.b transportFactoryProvider) {
        Intrinsics.checkNotNullParameter(transportFactoryProvider, "transportFactoryProvider");
        this.a = transportFactoryProvider;
    }

    public final void a(O sessionEvent) {
        Intrinsics.checkNotNullParameter(sessionEvent, "sessionEvent");
        ((com.google.android.datatransport.runtime.o) ((com.google.android.datatransport.f) this.a.get())).a("FIREBASE_APPQUALITY_SESSION", new com.google.android.datatransport.c("json"), new com.google.android.material.search.a(this, 15)).a(new com.google.android.datatransport.a(sessionEvent, com.google.android.datatransport.d.a, null), new com.facebook.appevents.k(16));
    }
}

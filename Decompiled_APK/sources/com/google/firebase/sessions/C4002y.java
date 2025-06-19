package com.google.firebase.sessions;

import kotlin.coroutines.CoroutineContext;

/* renamed from: com.google.firebase.sessions.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4002y implements com.google.firebase.sessions.dagger.internal.b {
    public final com.google.firebase.sessions.dagger.internal.c a;
    public final javax.inject.a b;
    public final com.google.firebase.sessions.dagger.internal.c c;
    public final javax.inject.a d;

    public C4002y(com.google.firebase.sessions.dagger.internal.c cVar, javax.inject.a aVar, com.google.firebase.sessions.dagger.internal.c cVar2, javax.inject.a aVar2) {
        this.a = cVar;
        this.b = aVar;
        this.c = cVar2;
        this.d = aVar2;
    }

    @Override // javax.inject.a
    public final Object get() {
        return new C3994p((com.google.firebase.h) this.a.a, (com.google.firebase.sessions.settings.j) this.b.get(), (CoroutineContext) this.c.a, (d0) this.d.get());
    }
}

package com.google.firebase.sessions;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes2.dex */
public final class V implements com.google.firebase.sessions.dagger.internal.b {
    public final /* synthetic */ int a;
    public final com.google.firebase.sessions.dagger.internal.c b;
    public final com.google.firebase.sessions.dagger.internal.c c;
    public final javax.inject.a d;
    public final javax.inject.a e;
    public final javax.inject.a f;

    public /* synthetic */ V(com.google.firebase.sessions.dagger.internal.c cVar, com.google.firebase.sessions.dagger.internal.c cVar2, javax.inject.a aVar, javax.inject.a aVar2, javax.inject.a aVar3, int i) {
        this.a = i;
        this.b = cVar;
        this.c = cVar2;
        this.d = aVar;
        this.e = aVar2;
        this.f = aVar3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v21, types: [com.google.firebase.sessions.dagger.a] */
    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new U((com.google.firebase.h) this.b.a, (com.google.firebase.installations.d) this.c.a, (com.google.firebase.sessions.settings.j) this.d.get(), (C3990l) this.e.get(), (CoroutineContext) ((com.google.firebase.sessions.dagger.internal.c) this.f).a);
            default:
                CoroutineContext coroutineContext = (CoroutineContext) this.b.a;
                com.google.firebase.installations.d dVar = (com.google.firebase.installations.d) this.c.a;
                C3980b c3980b = (C3980b) this.d.get();
                com.google.firebase.sessions.settings.g gVar = (com.google.firebase.sessions.settings.g) this.e.get();
                javax.inject.a aVar = this.f;
                return new com.google.firebase.sessions.settings.e(coroutineContext, dVar, c3980b, gVar, aVar instanceof com.google.firebase.sessions.dagger.a ? (com.google.firebase.sessions.dagger.a) aVar : new com.google.firebase.sessions.dagger.internal.a(aVar));
        }
    }
}

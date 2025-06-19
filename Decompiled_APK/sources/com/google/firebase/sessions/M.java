package com.google.firebase.sessions;

import androidx.datastore.core.InterfaceC1076h;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes2.dex */
public final class M implements com.google.firebase.sessions.dagger.internal.b {
    public final /* synthetic */ int a = 0;
    public final javax.inject.a b;
    public final com.google.firebase.sessions.dagger.internal.c c;

    public M(javax.inject.a aVar, com.google.firebase.sessions.dagger.internal.c cVar) {
        this.b = aVar;
        this.c = cVar;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new L((CoroutineContext) this.c.a, (InterfaceC1076h) this.b.get());
            default:
                return new com.google.firebase.sessions.settings.g((C3980b) this.b.get(), (CoroutineContext) this.c.a);
        }
    }

    public M(com.google.firebase.sessions.dagger.internal.c cVar, javax.inject.a aVar) {
        this.c = cVar;
        this.b = aVar;
    }
}

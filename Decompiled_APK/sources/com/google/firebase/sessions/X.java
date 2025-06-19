package com.google.firebase.sessions;

/* loaded from: classes2.dex */
public final class X implements com.google.firebase.sessions.dagger.internal.b {
    public final /* synthetic */ int a;
    public final javax.inject.a b;
    public final javax.inject.a c;

    public /* synthetic */ X(javax.inject.a aVar, javax.inject.a aVar2, int i) {
        this.a = i;
        this.b = aVar;
        this.c = aVar2;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new W((f0) this.b.get(), (g0) this.c.get());
            default:
                return new com.google.firebase.sessions.settings.j((com.google.firebase.sessions.settings.o) this.b.get(), (com.google.firebase.sessions.settings.o) this.c.get());
        }
    }
}

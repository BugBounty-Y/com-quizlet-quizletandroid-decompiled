package com.google.firebase.perf;

import com.google.firebase.h;
import com.google.firebase.perf.config.RemoteConfigManager;
import com.google.firebase.perf.session.SessionManager;

/* loaded from: classes2.dex */
public final class d implements dagger.internal.c {
    public final com.google.firebase.perf.injection.modules.b a;
    public final com.google.firebase.perf.injection.modules.b b;
    public final com.google.firebase.perf.injection.modules.b c;
    public final com.google.firebase.perf.injection.modules.b d;
    public final com.google.firebase.perf.injection.modules.a e;
    public final com.google.firebase.perf.injection.modules.a f;
    public final com.google.firebase.perf.injection.modules.a g;

    public d(com.google.firebase.perf.injection.modules.b bVar, com.google.firebase.perf.injection.modules.b bVar2, com.google.firebase.perf.injection.modules.b bVar3, com.google.firebase.perf.injection.modules.b bVar4, com.google.firebase.perf.injection.modules.a aVar, com.google.firebase.perf.injection.modules.a aVar2, com.google.firebase.perf.injection.modules.a aVar3) {
        this.a = bVar;
        this.b = bVar2;
        this.c = bVar3;
        this.d = bVar4;
        this.e = aVar;
        this.f = aVar2;
        this.g = aVar3;
    }

    @Override // javax.inject.a
    public final Object get() {
        return new b((h) this.a.get(), (com.google.firebase.inject.b) this.b.get(), (com.google.firebase.installations.d) this.c.get(), (com.google.firebase.inject.b) this.d.get(), (RemoteConfigManager) this.e.get(), (com.google.firebase.perf.config.a) this.f.get(), (SessionManager) this.g.get());
    }
}

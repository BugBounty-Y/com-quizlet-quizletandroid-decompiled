package com.google.android.gms.common.api.internal;

import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class p extends com.google.android.gms.common.api.h {
    public final com.google.android.gms.common.api.e b;

    public p(com.google.android.gms.common.api.e eVar) {
        this.b = eVar;
    }

    public final com.google.android.gms.auth.api.signin.internal.f a(com.google.android.gms.auth.api.signin.internal.f fVar) {
        com.google.android.gms.common.api.e eVar = this.b;
        eVar.getClass();
        fVar.zak();
        C1647e c1647e = eVar.k;
        c1647e.getClass();
        u uVar = new u(new z(fVar), c1647e.i.get(), eVar);
        Ls ls = c1647e.n;
        ls.sendMessage(ls.obtainMessage(4, uVar));
        return fVar;
    }
}

package com.google.firebase.remoteconfig.internal;

/* loaded from: classes2.dex */
public final class g {
    public final /* synthetic */ h a;

    public g(h hVar) {
        this.a = hVar;
    }

    public final void a() {
        h hVar = this.a;
        synchronized (hVar) {
            hVar.d = true;
        }
        this.a.g();
    }
}

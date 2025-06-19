package com.google.firebase.components;

import androidx.camera.camera2.internal.C0143u;

/* loaded from: classes2.dex */
public final class o implements com.google.firebase.inject.b {
    public static final n c = new n(0);
    public static final f d = new f(1);
    public com.google.firebase.inject.a a;
    public volatile com.google.firebase.inject.b b;

    public o(n nVar, com.google.firebase.inject.b bVar) {
        this.a = nVar;
        this.b = bVar;
    }

    public final void a(com.google.firebase.inject.a aVar) {
        com.google.firebase.inject.b bVar;
        com.google.firebase.inject.b bVar2;
        com.google.firebase.inject.b bVar3 = this.b;
        f fVar = d;
        if (bVar3 != fVar) {
            aVar.i(bVar3);
            return;
        }
        synchronized (this) {
            bVar = this.b;
            if (bVar != fVar) {
                bVar2 = bVar;
            } else {
                this.a = new C0143u(22, this.a, aVar);
                bVar2 = null;
            }
        }
        if (bVar2 != null) {
            aVar.i(bVar);
        }
    }

    @Override // com.google.firebase.inject.b
    public final Object get() {
        return this.b.get();
    }
}

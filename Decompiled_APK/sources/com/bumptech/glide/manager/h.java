package com.bumptech.glide.manager;

import androidx.annotation.NonNull;
import androidx.lifecycle.A;
import androidx.lifecycle.B;
import androidx.lifecycle.C;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1238a0;
import androidx.lifecycle.J;
import androidx.lifecycle.L;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class h implements g, I {
    public final HashSet a = new HashSet();
    public final C b;

    public h(C c) {
        this.b = c;
        c.a(this);
    }

    @Override // com.bumptech.glide.manager.g
    public final void a(i iVar) {
        this.a.add(iVar);
        B b = ((L) this.b).d;
        if (b == B.a) {
            iVar.onDestroy();
        } else if (b.a(B.d)) {
            iVar.onStart();
        } else {
            iVar.onStop();
        }
    }

    @Override // com.bumptech.glide.manager.g
    public final void c(i iVar) {
        this.a.remove(iVar);
    }

    @InterfaceC1238a0(A.ON_DESTROY)
    public void onDestroy(@NonNull J j) {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((i) it2.next()).onDestroy();
        }
        j.getLifecycle().b(this);
    }

    @InterfaceC1238a0(A.ON_START)
    public void onStart(@NonNull J j) {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((i) it2.next()).onStart();
        }
    }

    @InterfaceC1238a0(A.ON_STOP)
    public void onStop(@NonNull J j) {
        Iterator it2 = com.bumptech.glide.util.m.e(this.a).iterator();
        while (it2.hasNext()) {
            ((i) it2.next()).onStop();
        }
    }
}

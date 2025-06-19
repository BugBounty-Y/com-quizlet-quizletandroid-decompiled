package com.google.firebase.crashlytics.internal;

import com.google.firebase.components.o;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class a {
    public static final d c = new d();
    public final o a;
    public final AtomicReference b = new AtomicReference(null);

    public a(o oVar) {
        this.a = oVar;
        oVar.a(new com.google.android.material.search.a(this, 4));
    }

    public final d a(String str) {
        a aVar = (a) this.b.get();
        return aVar == null ? c : aVar.a(str);
    }

    public final boolean b() {
        a aVar = (a) this.b.get();
        return aVar != null && aVar.b();
    }

    public final boolean c(String str) {
        a aVar = (a) this.b.get();
        return aVar != null && aVar.c(str);
    }
}

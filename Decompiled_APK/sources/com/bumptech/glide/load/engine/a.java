package com.bumptech.glide.load.engine;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class a extends WeakReference {
    public final p a;
    public final boolean b;
    public v c;

    public a(p pVar, q qVar, ReferenceQueue referenceQueue) {
        super(qVar, referenceQueue);
        com.bumptech.glide.util.f.c(pVar, "Argument must not be null");
        this.a = pVar;
        boolean z = qVar.a;
        this.c = null;
        this.b = z;
    }
}

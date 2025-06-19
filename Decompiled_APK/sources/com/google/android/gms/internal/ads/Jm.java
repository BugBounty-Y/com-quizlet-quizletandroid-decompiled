package com.google.android.gms.internal.ads;

import java.lang.ref.WeakReference;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Jm {
    public final WeakReference a;
    public final Executor b;
    public final /* synthetic */ C2580rn c;

    public Jm(C2580rn c2580rn, C2006eG c2006eG, Executor executor) {
        this.c = c2580rn;
        this.a = new WeakReference(c2006eG);
        this.b = executor;
    }
}

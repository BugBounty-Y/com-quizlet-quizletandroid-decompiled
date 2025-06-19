package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Zj implements Callable {
    public final androidx.work.impl.model.c a;
    public final Context b;
    public final Hk c;
    public final C2107gm d;
    public final Executor e;
    public final P4 f;
    public final VersionInfoParcel g;
    public final C2584rr h;
    public final BinderC2408nm i;
    public final C2067fq j;

    public Zj(Context context, Executor executor, P4 p4, VersionInfoParcel versionInfoParcel, androidx.work.impl.model.c cVar, C2107gm c2107gm, C2584rr c2584rr, Hk hk, BinderC2408nm binderC2408nm, C2067fq c2067fq) {
        this.b = context;
        this.e = executor;
        this.f = p4;
        this.g = versionInfoParcel;
        this.a = cVar;
        this.d = c2107gm;
        this.h = c2584rr;
        this.c = hk;
        this.i = binderC2408nm;
        this.j = c2067fq;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        C1843ak c1843ak = new C1843ak(this);
        synchronized (c1843ak) {
            C2889yv c2889yvL = AbstractC2025es.L(AbstractC2025es.I(new androidx.compose.ui.node.V(c1843ak.c, c1843ak.f, c1843ak.g, c1843ak.b, c1843ak.k, c1843ak.l, c1843ak.d, (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R3), 5), AbstractC2270kd.f), new C1804Yb(c1843ak, 1), c1843ak.e);
            c1843ak.m = c2889yvL;
            AbstractC1972di.f(c2889yvL, "NativeJavascriptExecutor.initializeEngine");
        }
        return c1843ak;
    }
}

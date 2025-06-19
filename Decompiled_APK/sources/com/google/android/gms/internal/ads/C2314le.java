package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.le, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2314le extends AbstractC2656td {
    public final C1674Cd c;
    public S4 d;
    public C2785wd e;
    public boolean f;
    public int g;

    public C2314le(Context context, C1674Cd c1674Cd) {
        super(context);
        this.g = 1;
        this.f = false;
        this.c = c1674Cd;
        c1674Cd.a(this);
    }

    public final boolean E() {
        int i = this.g;
        return (i == 1 || i == 2 || this.d == null) ? false : true;
    }

    public final void F(int i) {
        C1686Ed c1686Ed = this.b;
        C1674Cd c1674Cd = this.c;
        if (i == 4) {
            c1674Cd.b();
            c1686Ed.d = true;
            c1686Ed.a();
        } else if (this.g == 4) {
            c1674Cd.m = false;
            c1686Ed.d = false;
            c1686Ed.a();
        }
        this.g = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int j() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int k() {
        return E() ? 0 : -1;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int l() {
        return E() ? 0 : -1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1680Dd
    public final void m() {
        if (this.d != null) {
            this.b.getClass();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int n() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int o() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long p() {
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long q() {
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long r() {
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final String s() {
        return "ImmersivePlayer";
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void t() {
        com.google.android.gms.ads.internal.util.A.l("AdImmersivePlayerView pause");
        if (E() && ((AtomicBoolean) this.d.b).get()) {
            ((AtomicBoolean) this.d.b).set(false);
            F(5);
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2271ke(this, 2));
        }
    }

    @Override // android.view.View
    public final String toString() {
        return android.support.v4.media.session.a.l(C2314le.class.getName(), "@", Integer.toHexString(hashCode()));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void u() {
        com.google.android.gms.ads.internal.util.A.l("AdImmersivePlayerView play");
        if (E()) {
            ((AtomicBoolean) this.d.b).set(true);
            F(4);
            this.a.c = true;
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2271ke(this, 1));
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void v(int i) {
        com.google.android.gms.ads.internal.util.A.l("AdImmersivePlayerView seek " + i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void w(C2785wd c2785wd) {
        this.e = c2785wd;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void x(String str) {
        if (str != null) {
            Uri.parse(str).toString();
            this.d = new S4(9);
            F(3);
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2271ke(this, 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void y() {
        com.google.android.gms.ads.internal.util.A.l("AdImmersivePlayerView stop");
        S4 s4 = this.d;
        if (s4 != null) {
            ((AtomicBoolean) s4.b).set(false);
            this.d = null;
            F(1);
        }
        this.c.c();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void z(float f, float f2) {
    }
}

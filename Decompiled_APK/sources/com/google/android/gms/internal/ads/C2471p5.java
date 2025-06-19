package com.google.android.gms.internal.ads;

import android.view.View;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.p5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2471p5 extends AbstractCallableC2599s5 {
    public final ViewOnAttachStateChangeListenerC1952d5 h;
    public final long i;

    public C2471p5(Z4 z4, C1864b4 c1864b4, int i, ViewOnAttachStateChangeListenerC1952d5 viewOnAttachStateChangeListenerC1952d5) {
        super(z4, "YdsvNQpLn71zCPsmNiBmaxgvKAoUotN+t67Ej8NmXEez61kI/ElwL7USsI8xuH+E", "BTo9KBR1VAIklcWQcnKn1k6hpYvG+18rom++PUlQVcU=", c1864b4, i, 53);
        this.h = viewOnAttachStateChangeListenerC1952d5;
        if (viewOnAttachStateChangeListenerC1952d5 != null) {
            if (viewOnAttachStateChangeListenerC1952d5.l <= -2) {
                WeakReference weakReference = viewOnAttachStateChangeListenerC1952d5.h;
                if ((weakReference != null ? (View) weakReference.get() : null) == null) {
                    viewOnAttachStateChangeListenerC1952d5.l = -3L;
                }
            }
            this.i = viewOnAttachStateChangeListenerC1952d5.l;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        if (this.h != null) {
            long jLongValue = ((Long) this.e.invoke(null, Long.valueOf(this.i))).longValue();
            C1864b4 c1864b4 = this.d;
            c1864b4.e();
            C2384n4.Q((C2384n4) c1864b4.b, jLongValue);
        }
    }
}

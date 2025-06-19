package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import androidx.collection.C0205c;
import androidx.collection.C0208f;
import java.util.Iterator;

/* renamed from: com.google.android.gms.measurement.internal.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3884o extends AbstractC3886p {
    public final C0208f c;
    public final C0208f d;
    public long e;

    public C3884o(Y y) {
        super(y);
        this.d = new C0208f(0);
        this.c = new C0208f(0);
    }

    public final void T(long j, String str) {
        Y y = (Y) this.b;
        if (str == null || str.length() == 0) {
            I i = y.i;
            Y.k(i);
            i.g.f("Ad unit id must be a non-empty string");
        } else {
            X x = y.j;
            Y.k(x);
            x.c0(new RunnableC3856a(this, str, j, 0));
        }
    }

    public final void U(long j, String str) {
        Y y = (Y) this.b;
        if (str == null || str.length() == 0) {
            I i = y.i;
            Y.k(i);
            i.g.f("Ad unit id must be a non-empty string");
        } else {
            X x = y.j;
            Y.k(x);
            x.c0(new RunnableC3856a(this, str, j, 1));
        }
    }

    public final void V(long j) {
        O0 o0 = ((Y) this.b).o;
        Y.j(o0);
        L0 l0Y = o0.Y(false);
        C0208f c0208f = this.c;
        Iterator it2 = ((C0205c) c0208f.keySet()).iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            X(str, j - ((Long) c0208f.get(str)).longValue(), l0Y);
        }
        if (!c0208f.isEmpty()) {
            W(j - this.e, l0Y);
        }
        Y(j);
    }

    public final void W(long j, L0 l0) {
        Y y = (Y) this.b;
        if (l0 == null) {
            I i = y.i;
            Y.k(i);
            i.o.f("Not logging ad exposure. No active activity");
        } else {
            if (j < 1000) {
                I i2 = y.i;
                Y.k(i2);
                i2.o.g("Not logging ad exposure. Less than 1000 ms. exposure", Long.valueOf(j));
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putLong("_xt", j);
            x1.h0(l0, bundle, true);
            D0 d0 = y.p;
            Y.j(d0);
            d0.c0("am", "_xa", bundle);
        }
    }

    public final void X(String str, long j, L0 l0) {
        Y y = (Y) this.b;
        if (l0 == null) {
            I i = y.i;
            Y.k(i);
            i.o.f("Not logging ad unit exposure. No active activity");
        } else {
            if (j < 1000) {
                I i2 = y.i;
                Y.k(i2);
                i2.o.g("Not logging ad unit exposure. Less than 1000 ms. exposure", Long.valueOf(j));
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putString("_ai", str);
            bundle.putLong("_xt", j);
            x1.h0(l0, bundle, true);
            D0 d0 = y.p;
            Y.j(d0);
            d0.c0("am", "_xu", bundle);
        }
    }

    public final void Y(long j) {
        C0208f c0208f = this.c;
        Iterator it2 = ((C0205c) c0208f.keySet()).iterator();
        while (it2.hasNext()) {
            c0208f.put((String) it2.next(), Long.valueOf(j));
        }
        if (c0208f.isEmpty()) {
            return;
        }
        this.e = j;
    }
}

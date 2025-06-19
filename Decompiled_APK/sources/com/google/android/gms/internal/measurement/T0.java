package com.google.android.gms.internal.measurement;

import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class T0 extends V1 {
    public final long i() {
        return ((U0) this.b).p();
    }

    public final long k() {
        return ((U0) this.b).q();
    }

    public final void l(W0 w0) {
        h();
        U0.w((U0) this.b, (X0) w0.f());
    }

    public final void m(X0 x0) {
        h();
        U0.w((U0) this.b, x0);
    }

    public final X0 n(int i) {
        return ((U0) this.b).s(i);
    }

    public final String o() {
        return ((U0) this.b).t();
    }

    public final List p() {
        return Collections.unmodifiableList(((U0) this.b).u());
    }
}

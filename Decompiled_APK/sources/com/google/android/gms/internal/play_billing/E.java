package com.google.android.gms.internal.play_billing;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class E extends AbstractC3809k implements Serializable {
    public static final E b;
    public static final E c;
    public final transient Q a;

    static {
        C3850y c3850y = B.b;
        b = new E(Q.e);
        Object[] objArr = {O.c};
        for (int i = 0; i < 1; i++) {
            if (objArr[i] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i, "at index "));
            }
        }
        c = new E(B.m(1, objArr));
    }

    public E(Q q) {
        this.a = q;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3809k
    public final /* bridge */ /* synthetic */ G a() {
        Q q = this.a;
        return q.isEmpty() ? X.i : new Y(q, M.c);
    }
}

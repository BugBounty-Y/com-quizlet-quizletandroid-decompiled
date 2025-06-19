package com.google.android.gms.internal.play_billing;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Z extends G {
    public final transient Object c;

    public Z(Object obj) {
        this.c = obj;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int a(Object[] objArr) {
        objArr[0] = this.c;
        return 1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.c.equals(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.G, com.google.android.gms.internal.play_billing.AbstractC3844w
    public final B e() {
        Object[] objArr = {this.c};
        for (int i = 0; i < 1; i++) {
            C3850y c3850y = B.b;
            if (objArr[i] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i, "at index "));
            }
        }
        return B.m(1, objArr);
    }

    @Override // com.google.android.gms.internal.play_billing.G, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.c.hashCode();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return new J(this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return 1;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        return android.support.v4.media.session.a.B("[", this.c.toString(), "]");
    }
}

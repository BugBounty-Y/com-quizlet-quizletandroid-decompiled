package com.google.android.gms.internal.fido;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class B extends AbstractC2951o {
    public final transient Object d;

    public B(Object obj) {
        this.d = obj;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int a(Object[] objArr) {
        objArr[0] = this.d;
        return 1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.equals(obj);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final D e() {
        return new C2955t(this.d);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.d.hashCode();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return new C2955t(this.d);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o
    public final AbstractC2949m k() {
        Object[] objArr = {this.d};
        for (int i = 0; i < 1; i++) {
            C2945i c2945i = AbstractC2949m.b;
            if (objArr[i] == null) {
                throw new NullPointerException(android.support.v4.media.session.a.f(i, "at index "));
            }
        }
        return AbstractC2949m.k(1, objArr);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return 1;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        return android.support.v4.media.session.a.B("[", this.d.toString(), "]");
    }
}

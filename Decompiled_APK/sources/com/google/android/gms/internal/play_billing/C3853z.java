package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3853z extends B {
    public final transient B c;

    public C3853z(B b) {
        this.c = b;
    }

    @Override // com.google.android.gms.internal.play_billing.B, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.c.contains(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final boolean g() {
        return this.c.g();
    }

    @Override // java.util.List
    public final Object get(int i) {
        B b = this.c;
        Z0.h(i, b.size());
        return b.get((b.size() - 1) - i);
    }

    @Override // com.google.android.gms.internal.play_billing.B, java.util.List
    public final int indexOf(Object obj) {
        int iLastIndexOf = this.c.lastIndexOf(obj);
        if (iLastIndexOf >= 0) {
            return (r0.size() - 1) - iLastIndexOf;
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.play_billing.B
    public final B j() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.play_billing.B, java.util.List
    /* renamed from: k */
    public final B subList(int i, int i2) {
        B b = this.c;
        Z0.y(i, i2, b.size());
        return b.subList(b.size() - i2, b.size() - i).j();
    }

    @Override // com.google.android.gms.internal.play_billing.B, java.util.List
    public final int lastIndexOf(Object obj) {
        int iIndexOf = this.c.indexOf(obj);
        if (iIndexOf >= 0) {
            return (r0.size() - 1) - iIndexOf;
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.size();
    }
}

package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class A extends B {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ B e;

    public A(B b, int i, int i2) {
        this.e = b;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final boolean g() {
        return true;
    }

    @Override // java.util.List
    public final Object get(int i) {
        Z0.h(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final Object[] h() {
        return this.e.h();
    }

    @Override // com.google.android.gms.internal.play_billing.B, java.util.List
    /* renamed from: k, reason: merged with bridge method [inline-methods] */
    public final B subList(int i, int i2) {
        Z0.y(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

package com.google.android.gms.internal.mlkit_vision_common;

/* loaded from: classes2.dex */
public final class Q4 extends R4 {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ R4 e;

    public Q4(R4 r4, int i, int i2) {
        this.e = r4;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final Object[] e() {
        return this.e.e();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.R4, java.util.List
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final R4 subList(int i, int i2) {
        N3.g(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.List
    public final Object get(int i) {
        N3.f(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

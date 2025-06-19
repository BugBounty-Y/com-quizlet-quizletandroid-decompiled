package com.google.android.gms.internal.common;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3524r3;

/* loaded from: classes2.dex */
public final class d extends e {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ e e;

    public d(e eVar, int i, int i2) {
        this.e = eVar;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.common.a
    public final Object[] a() {
        return this.e.a();
    }

    @Override // com.google.android.gms.internal.common.a
    public final int b() {
        return this.e.b() + this.c;
    }

    @Override // com.google.android.gms.internal.common.a
    public final int c() {
        return this.e.b() + this.c + this.d;
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC3524r3.b(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // com.google.android.gms.internal.common.e, java.util.List
    /* renamed from: h */
    public final e subList(int i, int i2) {
        AbstractC3524r3.d(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

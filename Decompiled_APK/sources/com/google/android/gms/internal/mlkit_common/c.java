package com.google.android.gms.internal.mlkit_common;

import com.google.android.gms.internal.mlkit_vision_common.E3;

/* loaded from: classes2.dex */
public final class c extends d {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ d e;

    public c(d dVar, int i, int i2) {
        this.e = dVar;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final Object[] e() {
        return this.e.e();
    }

    @Override // com.google.android.gms.internal.mlkit_common.d, java.util.List
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final d subList(int i, int i2) {
        E3.c(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.List
    public final Object get(int i) {
        E3.a(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

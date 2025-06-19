package com.google.android.gms.internal.mlkit_vision_barcode;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3284w extends AbstractC3292x {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ AbstractC3292x e;

    public C3284w(AbstractC3292x abstractC3292x, int i, int i2) {
        this.e = abstractC3292x;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final Object[] e() {
        return this.e.e();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3292x, java.util.List
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final AbstractC3292x subList(int i, int i2) {
        com.google.android.gms.internal.mlkit_vision_common.I3.e(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.I3.d(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

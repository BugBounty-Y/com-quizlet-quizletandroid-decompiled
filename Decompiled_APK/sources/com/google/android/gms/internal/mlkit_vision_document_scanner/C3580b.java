package com.google.android.gms.internal.mlkit_vision_document_scanner;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3580b extends AbstractC3588c {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ AbstractC3588c e;

    public C3580b(AbstractC3588c abstractC3588c, int i, int i2) {
        this.e = abstractC3588c;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final Object[] e() {
        return this.e.e();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3588c, java.util.List
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final AbstractC3588c subList(int i, int i2) {
        com.google.android.gms.internal.mlkit_vision_common.P3.c(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.P3.b(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

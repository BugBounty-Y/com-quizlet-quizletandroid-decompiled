package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3604e extends AbstractC3588c {
    public static final C3604e e = new C3604e(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public C3604e(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3588c, com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final Object[] e() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.P3.b(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

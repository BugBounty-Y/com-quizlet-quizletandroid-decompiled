package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3636i extends AbstractC3588c {
    public final transient Object[] c;
    public final transient int d;
    public final transient int e = 1;

    public C3636i(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.P3.b(i, this.e);
        Object obj = this.c[i + i + this.d];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.e;
    }
}

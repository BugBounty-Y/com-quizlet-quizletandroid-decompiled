package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.AbstractMap;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3612f extends AbstractC3588c {
    public final /* synthetic */ C3620g c;

    public C3612f(C3620g c3620g) {
        this.c = c3620g;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        C3620g c3620g = this.c;
        com.google.android.gms.internal.mlkit_vision_common.P3.b(i, c3620g.e);
        int i2 = i + i;
        Object[] objArr = c3620g.d;
        Object obj = objArr[i2];
        Objects.requireNonNull(obj);
        Object obj2 = objArr[i2 + 1];
        Objects.requireNonNull(obj2);
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.e;
    }
}

package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3628h extends AbstractC3596d {
    public final transient com.google.android.gms.internal.mlkit_vision_barcode.G c;
    public final transient C3636i d;

    public C3628h(com.google.android.gms.internal.mlkit_vision_barcode.G g, C3636i c3636i) {
        this.c = g;
        this.d = c3636i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int a(Object[] objArr) {
        return this.d.a(objArr);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.c.get(obj) != null;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return this.d.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        this.c.getClass();
        return 1;
    }
}

package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Rt;
import java.util.List;
import java.util.ListIterator;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3172j extends C3145g implements ListIterator {
    public final /* synthetic */ Rt e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3172j(Rt rt) {
        super(rt);
        this.e = rt;
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        Rt rt = this.e;
        boolean zIsEmpty = rt.isEmpty();
        a();
        ((ListIterator) this.b).add(obj);
        ((C3199m) rt.g).getClass();
        if (zIsEmpty) {
            rt.a();
        }
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        a();
        return ((ListIterator) this.b).hasPrevious();
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        a();
        return ((ListIterator) this.b).nextIndex();
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        a();
        return ((ListIterator) this.b).previous();
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        a();
        return ((ListIterator) this.b).previousIndex();
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        a();
        ((ListIterator) this.b).set(obj);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3172j(Rt rt, int i) {
        super(rt, ((List) rt.c).listIterator(i));
        this.e = rt;
    }
}

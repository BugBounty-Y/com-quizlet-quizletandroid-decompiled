package com.google.android.gms.internal.fido;

/* renamed from: com.google.android.gms.internal.fido.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2947k extends AbstractC2949m {
    public final transient AbstractC2949m c;

    public C2947k(AbstractC2949m abstractC2949m) {
        this.c = abstractC2949m;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.c.contains(obj);
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC2949m abstractC2949m = this.c;
        AbstractC2937a.e(i, abstractC2949m.size());
        return abstractC2949m.get((abstractC2949m.size() - 1) - i);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m
    public final AbstractC2949m h() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, java.util.List
    public final int indexOf(Object obj) {
        int iLastIndexOf = this.c.lastIndexOf(obj);
        if (iLastIndexOf >= 0) {
            return (r0.size() - 1) - iLastIndexOf;
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, java.util.List
    /* renamed from: j */
    public final AbstractC2949m subList(int i, int i2) {
        AbstractC2949m abstractC2949m = this.c;
        AbstractC2937a.n(i, i2, abstractC2949m.size());
        return abstractC2949m.subList(abstractC2949m.size() - i2, abstractC2949m.size() - i).h();
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, java.util.List
    public final int lastIndexOf(Object obj) {
        int iIndexOf = this.c.indexOf(obj);
        if (iIndexOf >= 0) {
            return (r0.size() - 1) - iIndexOf;
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.size();
    }
}

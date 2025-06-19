package com.google.android.gms.internal.fido;

/* renamed from: com.google.android.gms.internal.fido.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2948l extends AbstractC2949m {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ AbstractC2949m e;

    public C2948l(AbstractC2949m abstractC2949m, int i, int i2) {
        this.e = abstractC2949m;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final Object[] g() {
        return this.e.g();
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC2937a.e(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, java.util.List
    /* renamed from: j */
    public final AbstractC2949m subList(int i, int i2) {
        AbstractC2937a.n(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ku, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2287ku extends AbstractC2330lu {
    public final transient int c;
    public final transient int d;
    public final /* synthetic */ AbstractC2330lu e;

    public C2287ku(AbstractC2330lu abstractC2330lu, int i, int i2) {
        this.e = abstractC2330lu;
        this.c = i;
        this.d = i2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int b() {
        return this.e.c() + this.c + this.d;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int c() {
        return this.e.c() + this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC1981ds.f(i, this.d);
        return this.e.get(i + this.c);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Object[] j() {
        return this.e.j();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2330lu, java.util.List
    /* renamed from: k */
    public final AbstractC2330lu subList(int i, int i2) {
        AbstractC1981ds.K(i, i2, this.d);
        int i3 = this.c;
        return this.e.subList(i + i3, i2 + i3);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}

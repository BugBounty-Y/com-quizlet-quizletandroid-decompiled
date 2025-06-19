package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.yA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2862yA extends C2905zA {
    public final int d;
    public final int e;

    public C2862yA(int i, byte[] bArr, int i2) {
        super(bArr);
        BA.t(i, i + i2, bArr.length);
        this.d = i;
        this.e = i2;
    }

    @Override // com.google.android.gms.internal.ads.C2905zA, com.google.android.gms.internal.ads.BA
    public final byte b(int i) {
        BA.x(i, this.e);
        return this.c[this.d + i];
    }

    @Override // com.google.android.gms.internal.ads.C2905zA, com.google.android.gms.internal.ads.BA
    public final byte c(int i) {
        return this.c[this.d + i];
    }

    @Override // com.google.android.gms.internal.ads.C2905zA, com.google.android.gms.internal.ads.BA
    public final int g() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.C2905zA, com.google.android.gms.internal.ads.BA
    public final void h(int i, int i2, byte[] bArr, int i3) {
        System.arraycopy(this.c, this.d + i, bArr, i2, i3);
    }

    @Override // com.google.android.gms.internal.ads.C2905zA
    public final int z() {
        return this.d;
    }
}

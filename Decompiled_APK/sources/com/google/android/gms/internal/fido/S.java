package com.google.android.gms.internal.fido;

/* loaded from: classes2.dex */
public final class S extends T {
    public final int d;
    public final int e;

    public S(int i, byte[] bArr, int i2) {
        super(bArr);
        T.j(i, i + i2, bArr.length);
        this.d = i;
        this.e = i2;
    }

    @Override // com.google.android.gms.internal.fido.T
    public final byte a(int i) {
        int i2 = this.e;
        if (((i2 - (i + 1)) | i) >= 0) {
            return this.b[this.d + i];
        }
        if (i < 0) {
            throw new ArrayIndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Index < 0: "));
        }
        throw new ArrayIndexOutOfBoundsException(androidx.compose.animation.d0.p("Index > length: ", i, ", ", i2));
    }

    @Override // com.google.android.gms.internal.fido.T
    public final byte b(int i) {
        return this.b[this.d + i];
    }

    @Override // com.google.android.gms.internal.fido.T
    public final int c() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.fido.T
    public final int e() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.fido.T
    public final void g(int i, byte[] bArr) {
        System.arraycopy(this.b, this.d, bArr, 0, i);
    }
}

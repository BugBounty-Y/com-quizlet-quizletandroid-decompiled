package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class T0 extends U0 {
    public final int d;

    public T0(int i, byte[] bArr) {
        super(bArr);
        U0.e(0, i, bArr.length);
        this.d = i;
    }

    @Override // com.google.android.gms.internal.play_billing.U0
    public final byte a(int i) {
        int i2 = this.d;
        if (((i2 - (i + 1)) | i) >= 0) {
            return this.b[i];
        }
        if (i < 0) {
            throw new ArrayIndexOutOfBoundsException(android.support.v4.media.session.a.f(i, "Index < 0: "));
        }
        throw new ArrayIndexOutOfBoundsException(androidx.compose.animation.d0.p("Index > length: ", i, ", ", i2));
    }

    @Override // com.google.android.gms.internal.play_billing.U0
    public final byte b(int i) {
        return this.b[i];
    }

    @Override // com.google.android.gms.internal.play_billing.U0
    public final int c() {
        return this.d;
    }
}

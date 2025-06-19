package com.google.android.gms.internal.ads;

import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class Uu extends OutputStream {
    public final /* synthetic */ int a;

    private final void a(int i) {
    }

    private final void d(int i) {
    }

    public final String toString() {
        switch (this.a) {
        }
        return "ByteStreams.nullOutputStream()";
    }

    @Override // java.io.OutputStream
    public final void write(int i) {
        int i2 = this.a;
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr) {
        switch (this.a) {
            case 0:
                bArr.getClass();
                break;
            default:
                bArr.getClass();
                break;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr, int i, int i2) {
        switch (this.a) {
            case 0:
                bArr.getClass();
                AbstractC1981ds.K(i, i2 + i, bArr.length);
                break;
            default:
                bArr.getClass();
                com.google.common.base.b.e(i, i2 + i, bArr.length);
                break;
        }
    }
}

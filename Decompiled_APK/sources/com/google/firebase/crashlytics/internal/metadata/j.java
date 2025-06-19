package com.google.firebase.crashlytics.internal.metadata;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes2.dex */
public final class j extends InputStream {
    public int a;
    public int b;
    public final /* synthetic */ l c;

    public j(l lVar, i iVar) {
        this.c = lVar;
        this.a = lVar.B(iVar.a + 4);
        this.b = iVar.b;
    }

    @Override // java.io.InputStream
    public final int read(byte[] bArr, int i, int i2) throws IOException {
        if (bArr == null) {
            throw new NullPointerException("buffer");
        }
        if ((i | i2) < 0 || i2 > bArr.length - i) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int i3 = this.b;
        if (i3 <= 0) {
            return -1;
        }
        if (i2 > i3) {
            i2 = i3;
        }
        int i4 = this.a;
        l lVar = this.c;
        lVar.q(i4, i, bArr, i2);
        this.a = lVar.B(this.a + i2);
        this.b -= i2;
        return i2;
    }

    @Override // java.io.InputStream
    public final int read() throws IOException {
        if (this.b == 0) {
            return -1;
        }
        l lVar = this.c;
        lVar.a.seek(this.a);
        int i = lVar.a.read();
        this.a = lVar.B(this.a + 1);
        this.b--;
        return i;
    }
}

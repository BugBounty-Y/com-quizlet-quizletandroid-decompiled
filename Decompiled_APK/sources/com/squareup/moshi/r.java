package com.squareup.moshi;

import okio.C5091h;
import okio.I;

/* loaded from: classes3.dex */
public final class r implements okio.E {
    public final /* synthetic */ s a;

    public r(s sVar) {
        this.a = sVar;
    }

    @Override // okio.E
    public final void L(C5091h c5091h, long j) {
        this.a.h.L(c5091h, j);
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        s sVar = this.a;
        if (sVar.q() != 9) {
            throw new AssertionError();
        }
        int i = sVar.a;
        sVar.a = i - 1;
        int[] iArr = sVar.d;
        int i2 = i - 2;
        iArr[i2] = iArr[i2] + 1;
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() {
        this.a.h.flush();
    }

    @Override // okio.E
    public final I h() {
        return I.d;
    }
}

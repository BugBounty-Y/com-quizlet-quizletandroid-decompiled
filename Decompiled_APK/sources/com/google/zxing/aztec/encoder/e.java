package com.google.zxing.aztec.encoder;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
public final class e extends g {
    public final short c;
    public final short d;

    public e(g gVar, int i, int i2) {
        super(gVar);
        this.c = (short) i;
        this.d = (short) i2;
    }

    @Override // com.google.zxing.aztec.encoder.g
    public final void a(com.google.zxing.common.a aVar, byte[] bArr) {
        aVar.c(this.c, this.d);
    }

    public final String toString() {
        short s = this.d;
        return SimpleComparison.LESS_THAN_OPERATION + Integer.toBinaryString((1 << s) | (((1 << s) - 1) & this.c) | (1 << s)).substring(1) + '>';
    }
}

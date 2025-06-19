package com.google.zxing.aztec.encoder;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
public final class a extends g {
    public final short c;
    public final short d;

    public a(g gVar, int i, int i2) {
        super(gVar);
        this.c = (short) i;
        this.d = (short) i2;
    }

    @Override // com.google.zxing.aztec.encoder.g
    public final void a(com.google.zxing.common.a aVar, byte[] bArr) {
        int i = 0;
        while (true) {
            short s = this.d;
            if (i >= s) {
                return;
            }
            if (i == 0 || (i == 31 && s <= 62)) {
                aVar.c(31, 5);
                if (s > 62) {
                    aVar.c(s - 31, 16);
                } else if (i == 0) {
                    aVar.c(Math.min((int) s, 31), 5);
                } else {
                    aVar.c(s - 31, 5);
                }
            }
            aVar.c(bArr[this.c + i], 8);
            i++;
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(SimpleComparison.LESS_THAN_OPERATION);
        sb.append((int) this.c);
        sb.append("::");
        sb.append((r1 + this.d) - 1);
        sb.append('>');
        return sb.toString();
    }
}

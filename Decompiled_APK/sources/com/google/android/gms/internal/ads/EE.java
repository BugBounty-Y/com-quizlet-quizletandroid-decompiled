package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* loaded from: classes2.dex */
public final class EE extends MC {
    public long j;
    public int k;
    public int l;

    public final int A() {
        return this.k;
    }

    public final boolean B(MC mc) {
        ByteBuffer byteBuffer;
        AbstractC1795We.B(!mc.s(1073741824));
        AbstractC1795We.B(!mc.s(268435456));
        AbstractC1795We.B(!mc.s(4));
        if (C()) {
            if (this.k >= this.l) {
                return false;
            }
            ByteBuffer byteBuffer2 = mc.e;
            if (byteBuffer2 != null && (byteBuffer = this.e) != null) {
                if (byteBuffer2.remaining() + byteBuffer.position() > 3072000) {
                    return false;
                }
            }
        }
        int i = this.k;
        this.k = i + 1;
        if (i == 0) {
            this.g = mc.g;
            if (mc.s(1)) {
                this.b = 1;
            }
        }
        ByteBuffer byteBuffer3 = mc.e;
        if (byteBuffer3 != null) {
            w(byteBuffer3.remaining());
            this.e.put(byteBuffer3);
        }
        this.j = mc.g;
        return true;
    }

    public final boolean C() {
        return this.k > 0;
    }

    @Override // com.google.android.gms.internal.ads.MC
    public final void v() {
        super.v();
        this.k = 0;
    }
}

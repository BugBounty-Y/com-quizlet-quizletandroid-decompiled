package com.google.android.gms.common;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class l extends k {
    public final byte[] d;

    public l(byte[] bArr) {
        super(Arrays.copyOfRange(bArr, 0, 25));
        this.d = bArr;
    }

    @Override // com.google.android.gms.common.k
    public final byte[] v3() {
        return this.d;
    }
}

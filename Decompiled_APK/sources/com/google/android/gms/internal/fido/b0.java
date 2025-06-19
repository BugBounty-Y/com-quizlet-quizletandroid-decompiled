package com.google.android.gms.internal.fido;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

/* loaded from: classes2.dex */
public abstract class b0 implements Comparable {
    public static int d(byte b) {
        return (b >> 5) & 7;
    }

    public static b0 e(byte... bArr) {
        bArr.getClass();
        d0 d0Var = new d0(new ByteArrayInputStream(Arrays.copyOf(bArr, bArr.length)));
        try {
            return AbstractC2937a.l(d0Var);
        } finally {
            try {
                d0Var.close();
            } catch (IOException unused) {
            }
        }
    }

    public abstract int a();

    public int b() {
        return 0;
    }

    public final b0 c(Class cls) throws zzho {
        if (cls.isInstance(this)) {
            return (b0) cls.cast(this);
        }
        throw new zzho(android.support.v4.media.session.a.m("Expected a ", cls.getName(), " value, but got ", getClass().getName()));
    }
}

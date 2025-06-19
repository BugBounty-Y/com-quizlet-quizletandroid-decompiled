package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.m0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2337m0 {
    public final int a;
    public final byte[] b;
    public final int c;
    public final int d;

    public C2337m0(int i, int i2, byte[] bArr, int i3) {
        this.a = i;
        this.b = bArr;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2337m0.class == obj.getClass()) {
            C2337m0 c2337m0 = (C2337m0) obj;
            if (this.a == c2337m0.a && this.c == c2337m0.c && this.d == c2337m0.d && Arrays.equals(this.b, c2337m0.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((Arrays.hashCode(this.b) + (this.a * 31)) * 31) + this.c) * 31) + this.d;
    }
}

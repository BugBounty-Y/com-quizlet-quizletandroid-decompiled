package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.a1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1817a1 extends W0 {
    public final String b;
    public final byte[] c;

    public C1817a1(String str, byte[] bArr) {
        super("PRIV");
        this.b = str;
        this.c = bArr;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1817a1.class == obj.getClass()) {
            C1817a1 c1817a1 = (C1817a1) obj;
            if (Objects.equals(this.b, c1817a1.b) && Arrays.equals(this.c, c1817a1.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.c) + ((this.b.hashCode() + 527) * 31);
    }

    @Override // com.google.android.gms.internal.ads.W0
    public final String toString() {
        return this.a + ": owner=" + this.b;
    }
}

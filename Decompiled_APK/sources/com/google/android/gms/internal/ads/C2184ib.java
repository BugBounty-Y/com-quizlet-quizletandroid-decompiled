package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.ib, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2184ib {
    public final int a;
    public final J9 b;
    public final boolean c;
    public final int[] d;
    public final boolean[] e;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
    }

    public C2184ib(J9 j9, boolean z, int[] iArr, boolean[] zArr) {
        int i = j9.a;
        this.a = i;
        AbstractC1795We.B(i == iArr.length && i == zArr.length);
        this.b = j9;
        this.c = z && i > 1;
        this.d = (int[]) iArr.clone();
        this.e = (boolean[]) zArr.clone();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2184ib.class == obj.getClass()) {
            C2184ib c2184ib = (C2184ib) obj;
            if (this.c == c2184ib.c && this.b.equals(c2184ib.b) && Arrays.equals(this.d, c2184ib.d) && Arrays.equals(this.e, c2184ib.e)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.e) + ((Arrays.hashCode(this.d) + (((this.b.hashCode() * 31) + (this.c ? 1 : 0)) * 31)) * 31);
    }
}

package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.x1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3849x1 {
    public final P0 a;
    public final String b;
    public final Object[] c;
    public final int d;

    public C3849x1(P0 p0, String str, Object[] objArr) {
        this.a = p0;
        this.b = str;
        this.c = objArr;
        char cCharAt = str.charAt(0);
        if (cCharAt < 55296) {
            this.d = cCharAt;
            return;
        }
        int i = cCharAt & 8191;
        int i2 = 13;
        int i3 = 1;
        while (true) {
            int i4 = i3 + 1;
            char cCharAt2 = str.charAt(i3);
            if (cCharAt2 < 55296) {
                this.d = i | (cCharAt2 << i2);
                return;
            } else {
                i |= (cCharAt2 & 8191) << i2;
                i2 += 13;
                i3 = i4;
            }
        }
    }

    public final int a() {
        int i = this.d;
        if ((i & 1) != 0) {
            return 1;
        }
        return (i & 4) == 4 ? 3 : 2;
    }
}

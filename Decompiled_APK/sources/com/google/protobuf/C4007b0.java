package com.google.protobuf;

/* renamed from: com.google.protobuf.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4007b0 {
    public final AbstractC4004a a;
    public final String b;
    public final Object[] c;
    public final int d;

    public C4007b0(AbstractC4004a abstractC4004a, String str, Object[] objArr) {
        this.a = abstractC4004a;
        this.b = str;
        this.c = objArr;
        char cCharAt = str.charAt(0);
        if (cCharAt < 55296) {
            this.d = cCharAt;
            return;
        }
        int i = cCharAt & 8191;
        int i2 = 1;
        int i3 = 13;
        while (true) {
            int i4 = i2 + 1;
            char cCharAt2 = str.charAt(i2);
            if (cCharAt2 < 55296) {
                this.d = i | (cCharAt2 << i3);
                return;
            } else {
                i |= (cCharAt2 & 8191) << i3;
                i3 += 13;
                i2 = i4;
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

package com.perimeterx.mobile_sdk.models;

import java.util.List;

/* loaded from: classes2.dex */
public final class b {
    public final long a;
    public final String b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;

    public b(List list) {
        this.a = Long.parseLong((String) list.get(2));
        this.b = (String) list.get(3);
        this.f = Integer.parseInt((String) list.get(4));
        this.g = Integer.parseInt((String) list.get(5));
        this.c = Integer.parseInt((String) list.get(6));
        this.d = Integer.parseInt((String) list.get(7));
        this.e = Integer.parseInt((String) list.get(8));
        this.h = Integer.parseInt((String) list.get(9));
    }

    public static int a(int i, int i2, int i3, int i4) {
        int i5 = i4 % 10;
        int i6 = i5 != 0 ? i3 % i5 : i3 % 10;
        int i7 = i * i;
        int i8 = i2 * i2;
        switch (i6) {
            case 0:
                return i7 + i2;
            case 1:
                return i + i8;
            case 2:
                return i7 * i2;
            case 3:
                return i ^ i2;
            case 4:
                return i - i8;
            case 5:
                int i9 = i + 783;
                return (i9 * i9) + i8;
            case 6:
                return (i ^ i2) + i2;
            case 7:
                return i7 - i8;
            case 8:
                return i * i2;
            case 9:
                return (i2 * i) - i;
            default:
                return -1;
        }
    }
}

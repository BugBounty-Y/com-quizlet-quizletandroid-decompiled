package com.google.android.gms.internal.ads;

import android.graphics.Color;

/* renamed from: com.google.android.gms.internal.ads.o2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2425o2 {
    public final String a;
    public final int b;
    public final Integer c;
    public final Integer d;
    public final float e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final int j;

    public C2425o2(String str, int i, Integer num, Integer num2, float f, boolean z, boolean z2, boolean z3, boolean z4, int i2) {
        this.a = str;
        this.b = i;
        this.c = num;
        this.d = num2;
        this.e = f;
        this.f = z;
        this.g = z2;
        this.h = z3;
        this.i = z4;
        this.j = i2;
    }

    public static Integer a(String str) {
        try {
            long j = str.startsWith("&H") ? Long.parseLong(str.substring(2), 16) : Long.parseLong(str);
            AbstractC1795We.B(j <= 4294967295L);
            return Integer.valueOf(Color.argb(AbstractC1981ds.k(((j >> 24) & 255) ^ 255), AbstractC1981ds.k(j & 255), AbstractC1981ds.k((j >> 8) & 255), AbstractC1981ds.k((j >> 16) & 255)));
        } catch (IllegalArgumentException e) {
            AbstractC2096gb.M("SsaStyle", "Failed to parse color expression: '" + str + "'", e);
            return null;
        }
    }

    public static boolean b(String str) throws NumberFormatException {
        try {
            int i = Integer.parseInt(str);
            return i == 1 || i == -1;
        } catch (NumberFormatException e) {
            AbstractC2096gb.M("SsaStyle", "Failed to parse boolean value: '" + str + "'", e);
            return false;
        }
    }
}

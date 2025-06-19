package com.google.android.gms.internal.ads;

import android.text.Layout;

/* renamed from: com.google.android.gms.internal.ads.v2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2725v2 {
    public String a;
    public int b;
    public boolean c;
    public int d;
    public boolean e;
    public float k;
    public String l;
    public Layout.Alignment o;
    public Layout.Alignment p;
    public C2553r2 r;
    public String t;
    public String u;
    public int f = -1;
    public int g = -1;
    public int h = -1;
    public int i = -1;
    public int j = -1;
    public int m = -1;
    public int n = -1;
    public int q = -1;
    public float s = Float.MAX_VALUE;

    public final String a() {
        return this.u;
    }

    public final String b() {
        return this.l;
    }

    public final String c() {
        return this.t;
    }

    public final void d(C2725v2 c2725v2) {
        int i;
        Layout.Alignment alignment;
        Layout.Alignment alignment2;
        String str;
        if (c2725v2 != null) {
            if (!this.c && c2725v2.c) {
                this.b = c2725v2.b;
                this.c = true;
            }
            if (this.h == -1) {
                this.h = c2725v2.h;
            }
            if (this.i == -1) {
                this.i = c2725v2.i;
            }
            if (this.a == null && (str = c2725v2.a) != null) {
                this.a = str;
            }
            if (this.f == -1) {
                this.f = c2725v2.f;
            }
            if (this.g == -1) {
                this.g = c2725v2.g;
            }
            if (this.n == -1) {
                this.n = c2725v2.n;
            }
            if (this.o == null && (alignment2 = c2725v2.o) != null) {
                this.o = alignment2;
            }
            if (this.p == null && (alignment = c2725v2.p) != null) {
                this.p = alignment;
            }
            if (this.q == -1) {
                this.q = c2725v2.q;
            }
            if (this.j == -1) {
                this.j = c2725v2.j;
                this.k = c2725v2.k;
            }
            if (this.r == null) {
                this.r = c2725v2.r;
            }
            if (this.s == Float.MAX_VALUE) {
                this.s = c2725v2.s;
            }
            if (this.t == null) {
                this.t = c2725v2.t;
            }
            if (this.u == null) {
                this.u = c2725v2.u;
            }
            if (!this.e && c2725v2.e) {
                this.d = c2725v2.d;
                this.e = true;
            }
            if (this.m != -1 || (i = c2725v2.m) == -1) {
                return;
            }
            this.m = i;
        }
    }
}

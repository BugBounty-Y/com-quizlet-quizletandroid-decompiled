package com.google.android.gms.internal.ads;

import android.graphics.Bitmap;
import android.text.Layout;
import android.text.Spanned;
import android.text.SpannedString;
import android.text.TextUtils;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Gg {
    public static final String A;
    public static final String B;
    public static final String C;
    public static final String D;
    public static final String E;
    public static final String F;
    public static final String G;
    public static final String p;
    public static final String q;
    public static final String r;
    public static final String s;
    public static final String t;
    public static final String u;
    public static final String v;
    public static final String w;
    public static final String x;
    public static final String y;
    public static final String z;
    public final CharSequence a;
    public final Layout.Alignment b;
    public final Layout.Alignment c;
    public final Bitmap d;
    public final float e;
    public final int f;
    public final int g;
    public final float h;
    public final int i;
    public final float j;
    public final float k;
    public final int l;
    public final float m;
    public final int n;
    public final float o;

    /* JADX WARN: Multi-variable type inference failed */
    static {
        int i = Integer.MIN_VALUE;
        float f = -3.4028235E38f;
        new Gg("", null, 0 == true ? 1 : 0, 0 == true ? 1 : 0, f, i, i, f, i, i, f, f, f, i, DefinitionKt.NO_Float_VALUE);
        String str = Yo.a;
        p = Integer.toString(0, 36);
        q = Integer.toString(17, 36);
        r = Integer.toString(1, 36);
        s = Integer.toString(2, 36);
        Integer.toString(3, 36);
        t = Integer.toString(18, 36);
        u = Integer.toString(4, 36);
        v = Integer.toString(5, 36);
        w = Integer.toString(6, 36);
        x = Integer.toString(7, 36);
        y = Integer.toString(8, 36);
        z = Integer.toString(9, 36);
        A = Integer.toString(10, 36);
        B = Integer.toString(11, 36);
        C = Integer.toString(12, 36);
        D = Integer.toString(13, 36);
        E = Integer.toString(14, 36);
        F = Integer.toString(15, 36);
        G = Integer.toString(16, 36);
    }

    public /* synthetic */ Gg(CharSequence charSequence, Layout.Alignment alignment, Layout.Alignment alignment2, Bitmap bitmap, float f, int i, int i2, float f2, int i3, int i4, float f3, float f4, float f5, int i5, float f6) {
        if (charSequence == null) {
            bitmap.getClass();
        } else {
            AbstractC1795We.B(bitmap == null);
        }
        if (charSequence instanceof Spanned) {
            this.a = SpannedString.valueOf(charSequence);
        } else {
            this.a = charSequence != null ? charSequence.toString() : null;
        }
        this.b = alignment;
        this.c = alignment2;
        this.d = bitmap;
        this.e = f;
        this.f = i;
        this.g = i2;
        this.h = f2;
        this.i = i3;
        this.j = f4;
        this.k = f5;
        this.l = i4;
        this.m = f3;
        this.n = i5;
        this.o = f6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || Gg.class != obj.getClass()) {
            return false;
        }
        Gg gg = (Gg) obj;
        if (!TextUtils.equals(this.a, gg.a) || this.b != gg.b || this.c != gg.c) {
            return false;
        }
        Bitmap bitmap = gg.d;
        Bitmap bitmap2 = this.d;
        if (bitmap2 == null) {
            if (bitmap != null) {
                return false;
            }
        } else if (bitmap == null || !bitmap2.sameAs(bitmap)) {
            return false;
        }
        return this.e == gg.e && this.f == gg.f && this.g == gg.g && this.h == gg.h && this.i == gg.i && this.j == gg.j && this.k == gg.k && this.l == gg.l && this.m == gg.m && this.n == gg.n && this.o == gg.o;
    }

    public final int hashCode() {
        Float fValueOf = Float.valueOf(this.e);
        Integer numValueOf = Integer.valueOf(this.f);
        Integer numValueOf2 = Integer.valueOf(this.g);
        Float fValueOf2 = Float.valueOf(this.h);
        Integer numValueOf3 = Integer.valueOf(this.i);
        Float fValueOf3 = Float.valueOf(this.j);
        Float fValueOf4 = Float.valueOf(this.k);
        Boolean bool = Boolean.FALSE;
        Integer numValueOf4 = Integer.valueOf(this.l);
        Float fValueOf5 = Float.valueOf(this.m);
        Integer numValueOf5 = Integer.valueOf(this.n);
        Float fValueOf6 = Float.valueOf(this.o);
        return Objects.hash(this.a, this.b, this.c, this.d, fValueOf, numValueOf, numValueOf2, fValueOf2, numValueOf3, fValueOf3, fValueOf4, bool, -16777216, numValueOf4, fValueOf5, numValueOf5, fValueOf6);
    }
}

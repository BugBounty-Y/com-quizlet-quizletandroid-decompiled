package com.airbnb.lottie.model;

import androidx.compose.animation.d0;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class d {
    public final ArrayList a;
    public final char b;
    public final double c;
    public final String d;
    public final String e;

    public d(ArrayList arrayList, char c, double d, String str, String str2) {
        this.a = arrayList;
        this.b = c;
        this.c = d;
        this.d = str;
        this.e = str2;
    }

    public static int a(String str, String str2, char c) {
        return str2.hashCode() + d0.e(c * 31, 31, str);
    }

    public final int hashCode() {
        return a(this.e, this.d, this.b);
    }
}

package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Collections;

/* renamed from: com.google.android.gms.internal.ads.iG, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2182iG {
    public static final B2 g = new B2(13);
    public static final B2 h = new B2(14);
    public int d;
    public int e;
    public int f;
    public final C2138hG[] b = new C2138hG[5];
    public final ArrayList a = new ArrayList();
    public int c = -1;

    public final float a() {
        int i = this.c;
        ArrayList arrayList = this.a;
        if (i != 0) {
            Collections.sort(arrayList, h);
            this.c = 0;
        }
        float f = this.e;
        int i2 = 0;
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            float f2 = 0.5f * f;
            C2138hG c2138hG = (C2138hG) arrayList.get(i3);
            i2 += c2138hG.b;
            if (i2 >= f2) {
                return c2138hG.c;
            }
        }
        if (arrayList.isEmpty()) {
            return Float.NaN;
        }
        return ((C2138hG) arrayList.get(arrayList.size() - 1)).c;
    }

    public final void b(float f, int i) {
        C2138hG c2138hG;
        int i2 = this.c;
        ArrayList arrayList = this.a;
        if (i2 != 1) {
            Collections.sort(arrayList, g);
            this.c = 1;
        }
        int i3 = this.f;
        C2138hG[] c2138hGArr = this.b;
        if (i3 > 0) {
            int i4 = i3 - 1;
            this.f = i4;
            c2138hG = c2138hGArr[i4];
        } else {
            c2138hG = new C2138hG();
        }
        int i5 = this.d;
        this.d = i5 + 1;
        c2138hG.a = i5;
        c2138hG.b = i;
        c2138hG.c = f;
        arrayList.add(c2138hG);
        this.e += i;
        while (true) {
            int i6 = this.e;
            if (i6 <= 2000) {
                return;
            }
            int i7 = i6 - 2000;
            C2138hG c2138hG2 = (C2138hG) arrayList.get(0);
            int i8 = c2138hG2.b;
            if (i8 <= i7) {
                this.e -= i8;
                arrayList.remove(0);
                int i9 = this.f;
                if (i9 < 5) {
                    this.f = i9 + 1;
                    c2138hGArr[i9] = c2138hG2;
                }
            } else {
                c2138hG2.b = i8 - i7;
                this.e -= i7;
            }
        }
    }
}

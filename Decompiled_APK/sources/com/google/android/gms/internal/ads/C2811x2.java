package com.google.android.gms.internal.ads;

import android.graphics.Rect;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.x2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2811x2 {
    public boolean b;
    public boolean c;
    public int[] d;
    public int e;
    public int f;
    public Rect g;
    public final int[] a = new int[4];
    public int h = -1;
    public int i = -1;

    public static int a(int i, int i2) {
        return (i & 16777215) | ((i2 * 17) << 24);
    }

    public final void b(C2466p0 c2466p0, boolean z, Rect rect, int[] iArr) {
        int i;
        int i2;
        int i3 = !z ? 1 : 0;
        int iWidth = rect.width();
        int i4 = i3 * iWidth;
        int iHeight = rect.height();
        while (true) {
            int i5 = 0;
            do {
                int iF = 0;
                for (int i6 = 1; iF < i6 && i6 <= 64; i6 <<= 2) {
                    if (c2466p0.a() < 4) {
                        i = -1;
                        i2 = 0;
                        break;
                    }
                    iF = (iF << 4) | c2466p0.f(4);
                }
                i = iF & 3;
                i2 = iF < 4 ? iWidth : iF >> 2;
                int iMin = Math.min(i2, iWidth - i5);
                if (iMin > 0) {
                    int i7 = i4 + iMin;
                    Arrays.fill(iArr, i4, i7, this.a[i]);
                    i5 += iMin;
                    i4 = i7;
                }
            } while (i5 < iWidth);
            i3 += 2;
            if (i3 >= iHeight) {
                return;
            }
            i4 = i3 * iWidth;
            c2466p0.j();
        }
    }
}

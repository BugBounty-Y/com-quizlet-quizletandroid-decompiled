package com.lyft.android.scissors;

import android.graphics.Rect;
import androidx.compose.animation.f0;

/* loaded from: classes2.dex */
public final class k {
    public final c a;
    public float d;
    public final float e;
    public Rect f;
    public float g;
    public int h;
    public int i;
    public int j;
    public int k;
    public int l;
    public int m;
    public float n = -1.0f;
    public final f0 o = new f0(5);
    public final f0[] b = new f0[2];
    public final f0[] c = new f0[2];

    public k(c cVar) {
        this.a = cVar;
        this.d = cVar.c;
        this.e = cVar.b;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0031  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            r8 = this;
            android.graphics.Rect r0 = r8.f
            if (r0 != 0) goto L5
            return
        L5:
            androidx.compose.animation.f0 r1 = r8.o
            float r2 = r1.c
            int r3 = r0.bottom
            float r4 = (float) r3
            float r5 = r4 - r2
            int r6 = r8.l
            float r7 = (float) r6
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 < 0) goto L18
            int r3 = r3 - r6
        L16:
            float r2 = (float) r3
            goto L21
        L18:
            float r4 = r2 - r4
            float r5 = (float) r6
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 < 0) goto L21
            int r3 = r3 + r6
            goto L16
        L21:
            float r3 = r1.b
            int r0 = r0.right
            int r4 = r8.m
            int r5 = r0 - r4
            float r5 = (float) r5
            int r5 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r5 > 0) goto L31
            int r0 = r0 - r4
        L2f:
            float r3 = (float) r0
            goto L3a
        L31:
            int r5 = r0 + r4
            float r5 = (float) r5
            int r5 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r5 <= 0) goto L3a
            int r0 = r0 + r4
            goto L2f
        L3a:
            r1.b = r3
            r1.c = r2
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.k.a():void");
    }

    public final void b() {
        float f = this.j;
        float f2 = this.n;
        this.m = (((int) (f * f2)) - this.h) / 2;
        this.l = (((int) (this.k * f2)) - this.i) / 2;
    }
}

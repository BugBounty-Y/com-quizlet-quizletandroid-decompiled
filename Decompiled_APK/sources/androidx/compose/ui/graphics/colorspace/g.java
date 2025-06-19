package androidx.compose.ui.graphics.colorspace;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public class g {
    public final c a;
    public final c b;
    public final c c;
    public final float[] d;

    public g(c cVar, c cVar2, c cVar3, float[] fArr) {
        this.a = cVar;
        this.b = cVar2;
        this.c = cVar3;
        this.d = fArr;
    }

    public long a(long j) {
        float fH = C0861v.h(j);
        float fG = C0861v.g(j);
        float fE = C0861v.e(j);
        float fD = C0861v.d(j);
        c cVar = this.b;
        long jD = cVar.d(fH, fG, fE);
        float fIntBitsToFloat = Float.intBitsToFloat((int) (jD >> 32));
        float fIntBitsToFloat2 = Float.intBitsToFloat((int) (jD & 4294967295L));
        float fE2 = cVar.e(fH, fG, fE);
        float[] fArr = this.d;
        if (fArr != null) {
            fIntBitsToFloat *= fArr[0];
            fIntBitsToFloat2 *= fArr[1];
            fE2 *= fArr[2];
        }
        float f = fIntBitsToFloat;
        float f2 = fIntBitsToFloat2;
        return this.c.f(f, f2, fE2, fD, this.a);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public g(androidx.compose.ui.graphics.colorspace.c r11, androidx.compose.ui.graphics.colorspace.c r12, int r13) {
        /*
            r10 = this;
            r0 = 2
            r1 = 1
            r2 = 0
            r3 = 3
            long r4 = r11.b
            long r6 = androidx.compose.ui.graphics.colorspace.b.a
            boolean r4 = androidx.compose.ui.graphics.colorspace.b.a(r4, r6)
            if (r4 == 0) goto L13
            androidx.compose.ui.graphics.colorspace.c r4 = androidx.compose.ui.graphics.colorspace.j.a(r11)
            goto L14
        L13:
            r4 = r11
        L14:
            long r8 = r12.b
            boolean r5 = androidx.compose.ui.graphics.colorspace.b.a(r8, r6)
            if (r5 == 0) goto L21
            androidx.compose.ui.graphics.colorspace.c r5 = androidx.compose.ui.graphics.colorspace.j.a(r12)
            goto L22
        L21:
            r5 = r12
        L22:
            if (r13 != r3) goto L69
            long r8 = r11.b
            boolean r13 = androidx.compose.ui.graphics.colorspace.b.a(r8, r6)
            long r8 = r12.b
            boolean r6 = androidx.compose.ui.graphics.colorspace.b.a(r8, r6)
            if (r13 == 0) goto L35
            if (r6 == 0) goto L35
            goto L69
        L35:
            if (r13 != 0) goto L39
            if (r6 == 0) goto L69
        L39:
            if (r13 == 0) goto L3c
            goto L3d
        L3c:
            r11 = r12
        L3d:
            androidx.compose.ui.graphics.colorspace.q r11 = (androidx.compose.ui.graphics.colorspace.q) r11
            float[] r7 = androidx.compose.ui.graphics.colorspace.j.e
            androidx.compose.ui.graphics.colorspace.s r11 = r11.d
            if (r13 == 0) goto L4a
            float[] r13 = r11.a()
            goto L4b
        L4a:
            r13 = r7
        L4b:
            if (r6 == 0) goto L51
            float[] r7 = r11.a()
        L51:
            r11 = r13[r2]
            r6 = r7[r2]
            float r11 = r11 / r6
            r6 = r13[r1]
            r8 = r7[r1]
            float r6 = r6 / r8
            r13 = r13[r0]
            r7 = r7[r0]
            float r13 = r13 / r7
            float[] r3 = new float[r3]
            r3[r2] = r11
            r3[r1] = r6
            r3[r0] = r13
            goto L6a
        L69:
            r3 = 0
        L6a:
            r10.<init>(r12, r4, r5, r3)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.colorspace.g.<init>(androidx.compose.ui.graphics.colorspace.c, androidx.compose.ui.graphics.colorspace.c, int):void");
    }
}

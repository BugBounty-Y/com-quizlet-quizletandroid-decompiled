package androidx.camera.camera2.internal;

import com.google.android.gms.internal.mlkit_vision_barcode.P4;

/* loaded from: classes.dex */
public final class q0 {
    public final /* synthetic */ int a = 1;
    public float b;
    public float c;
    public float d;
    public float e;

    public /* synthetic */ q0() {
    }

    public float a() {
        return this.e;
    }

    public float b() {
        return this.c;
    }

    public float c() {
        return this.d;
    }

    public float d() {
        return this.b;
    }

    public void e(float f, float f2, float f3, float f4) {
        this.b = Math.max(f, this.b);
        this.c = Math.max(f2, this.c);
        this.d = Math.min(f3, this.d);
        this.e = Math.min(f4, this.e);
    }

    public boolean f() {
        return this.b >= this.d || this.c >= this.e;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void g() {
        /*
            r6 = this;
            r0 = 1065353216(0x3f800000, float:1.0)
            float r1 = r6.c
            int r2 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            float r3 = r6.d
            if (r2 > 0) goto L29
            int r4 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r4 < 0) goto L29
            r6.b = r0
            int r4 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            r5 = 0
            if (r4 != 0) goto L17
        L15:
            r0 = r5
            goto L26
        L17:
            if (r2 != 0) goto L1a
            goto L26
        L1a:
            int r2 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r2 != 0) goto L1f
            goto L15
        L1f:
            float r1 = r0 / r1
            float r2 = r0 / r3
            float r0 = r0 - r2
            float r1 = r1 - r2
            float r0 = r0 / r1
        L26:
            r6.e = r0
            return
        L29:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r2 = "Requested zoomRatio 1.0 is not within valid range ["
            r0.<init>(r2)
            r0.append(r3)
            java.lang.String r2 = " , "
            r0.append(r2)
            r0.append(r1)
            java.lang.String r1 = "]"
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
            r1.<init>(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.q0.g():void");
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "MutableRect(" + P4.e(this.b) + ", " + P4.e(this.c) + ", " + P4.e(this.d) + ", " + P4.e(this.e) + ')';
            default:
                return super.toString();
        }
    }

    public q0(float f, float f2) {
        this.c = f;
        this.d = f2;
    }
}

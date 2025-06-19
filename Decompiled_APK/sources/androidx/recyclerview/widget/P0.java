package androidx.recyclerview.widget;

import com.comscore.streaming.ContentType;

/* loaded from: classes.dex */
public final class P0 {
    public int a;
    public int b;
    public int c;
    public int d;
    public int e;

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x005b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.recyclerview.widget.P0 b(java.lang.String r12) {
        /*
            java.lang.String r0 = "Format:"
            boolean r0 = r12.startsWith(r0)
            com.google.android.gms.internal.ads.AbstractC1795We.B(r0)
            r0 = 7
            java.lang.String r12 = r12.substring(r0)
            java.lang.String r0 = ","
            java.lang.String[] r12 = android.text.TextUtils.split(r12, r0)
            r0 = 0
            r1 = -1
            r2 = r0
            r3 = r1
            r4 = r3
            r5 = r4
            r6 = r5
        L1b:
            int r7 = r12.length
            if (r2 >= r7) goto L6f
            r7 = r12[r2]
            java.lang.String r7 = r7.trim()
            java.lang.String r7 = com.google.android.gms.internal.ads.AbstractC2543qs.f(r7)
            int r8 = r7.hashCode()
            r9 = 1
            r10 = 3
            r11 = 2
            switch(r8) {
                case 100571: goto L51;
                case 3556653: goto L47;
                case 109757538: goto L3d;
                case 109780401: goto L33;
                default: goto L32;
            }
        L32:
            goto L5b
        L33:
            java.lang.String r8 = "style"
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L5b
            r7 = r11
            goto L5c
        L3d:
            java.lang.String r8 = "start"
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L5b
            r7 = r0
            goto L5c
        L47:
            java.lang.String r8 = "text"
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L5b
            r7 = r10
            goto L5c
        L51:
            java.lang.String r8 = "end"
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L5b
            r7 = r9
            goto L5c
        L5b:
            r7 = r1
        L5c:
            if (r7 == 0) goto L6b
            if (r7 == r9) goto L69
            if (r7 == r11) goto L67
            if (r7 == r10) goto L65
            goto L6c
        L65:
            r5 = r2
            goto L6c
        L67:
            r6 = r2
            goto L6c
        L69:
            r4 = r2
            goto L6c
        L6b:
            r3 = r2
        L6c:
            int r2 = r2 + 1
            goto L1b
        L6f:
            if (r3 == r1) goto L85
            if (r4 == r1) goto L85
            if (r5 == r1) goto L85
            androidx.recyclerview.widget.P0 r12 = new androidx.recyclerview.widget.P0
            r12.<init>()
            r12.a = r3
            r12.b = r4
            r12.c = r6
            r12.d = r5
            r12.e = r7
            return r12
        L85:
            r12 = 0
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.P0.b(java.lang.String):androidx.recyclerview.widget.P0");
    }

    public boolean a() {
        int i = this.a;
        int i2 = 2;
        if ((i & 7) != 0) {
            int i3 = this.d;
            int i4 = this.b;
            if (((i3 > i4 ? 1 : i3 == i4 ? 2 : 4) & i) == 0) {
                return false;
            }
        }
        if ((i & ContentType.LONG_FORM_ON_DEMAND) != 0) {
            int i5 = this.d;
            int i6 = this.c;
            if ((((i5 > i6 ? 1 : i5 == i6 ? 2 : 4) << 4) & i) == 0) {
                return false;
            }
        }
        if ((i & 1792) != 0) {
            int i7 = this.e;
            int i8 = this.b;
            if ((((i7 > i8 ? 1 : i7 == i8 ? 2 : 4) << 8) & i) == 0) {
                return false;
            }
        }
        if ((i & 28672) != 0) {
            int i9 = this.e;
            int i10 = this.c;
            if (i9 > i10) {
                i2 = 1;
            } else if (i9 != i10) {
                i2 = 4;
            }
            if ((i & (i2 << 12)) == 0) {
                return false;
            }
        }
        return true;
    }
}

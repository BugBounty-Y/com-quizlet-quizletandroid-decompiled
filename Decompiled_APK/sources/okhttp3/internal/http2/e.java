package okhttp3.internal.http2;

import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes3.dex */
public abstract class e {
    public static final okio.k a;
    public static final String[] b;
    public static final String[] c;
    public static final String[] d;

    static {
        okio.k kVar = okio.k.d;
        a = com.quizlet.quizletandroid.ui.common.images.capture.b.i("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        b = new String[]{"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"};
        c = new String[64];
        String[] strArr = new String[256];
        for (int i = 0; i < 256; i++) {
            String binaryString = Integer.toBinaryString(i);
            Intrinsics.checkNotNullExpressionValue(binaryString, "toBinaryString(it)");
            strArr[i] = D.p(okhttp3.internal.b.j("%8s", binaryString), ' ', '0');
        }
        d = strArr;
        String[] strArr2 = c;
        strArr2[0] = "";
        strArr2[1] = "END_STREAM";
        int[] iArr = {1};
        strArr2[8] = "PADDED";
        int i2 = iArr[0];
        strArr2[i2 | 8] = android.support.v4.media.session.a.t(new StringBuilder(), strArr2[i2], "|PADDED");
        strArr2[4] = "END_HEADERS";
        strArr2[32] = "PRIORITY";
        strArr2[36] = "END_HEADERS|PRIORITY";
        int[] iArr2 = {4, 32, 36};
        for (int i3 = 0; i3 < 3; i3++) {
            int i4 = iArr2[i3];
            int i5 = iArr[0];
            String[] strArr3 = c;
            int i6 = i5 | i4;
            strArr3[i6] = strArr3[i5] + '|' + strArr3[i4];
            StringBuilder sb = new StringBuilder();
            sb.append(strArr3[i5]);
            sb.append('|');
            strArr3[i6 | 8] = android.support.v4.media.session.a.t(sb, strArr3[i4], "|PADDED");
        }
        int length = c.length;
        for (int i7 = 0; i7 < length; i7++) {
            String[] strArr4 = c;
            if (strArr4[i7] == null) {
                strArr4[i7] = d[i7];
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0068  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String a(int r4, int r5, int r6, int r7, boolean r8) {
        /*
            java.lang.String[] r0 = okhttp3.internal.http2.e.b
            int r1 = r0.length
            if (r6 >= r1) goto L8
            r0 = r0[r6]
            goto L16
        L8:
            java.lang.Integer r0 = java.lang.Integer.valueOf(r6)
            java.lang.Object[] r0 = new java.lang.Object[]{r0}
            java.lang.String r1 = "0x%02x"
            java.lang.String r0 = okhttp3.internal.b.j(r1, r0)
        L16:
            if (r7 != 0) goto L1b
            java.lang.String r6 = ""
            goto L6a
        L1b:
            r1 = 2
            java.lang.String[] r2 = okhttp3.internal.http2.e.d
            if (r6 == r1) goto L68
            r1 = 3
            if (r6 == r1) goto L68
            r1 = 4
            if (r6 == r1) goto L5f
            r1 = 6
            if (r6 == r1) goto L5f
            r1 = 7
            if (r6 == r1) goto L68
            r1 = 8
            if (r6 == r1) goto L68
            java.lang.String[] r1 = okhttp3.internal.http2.e.c
            int r3 = r1.length
            if (r7 >= r3) goto L3b
            r1 = r1[r7]
            kotlin.jvm.internal.Intrinsics.d(r1)
            goto L3d
        L3b:
            r1 = r2[r7]
        L3d:
            r2 = 5
            r3 = 0
            if (r6 != r2) goto L4e
            r2 = r7 & 4
            if (r2 == 0) goto L4e
            java.lang.String r6 = "HEADERS"
            java.lang.String r7 = "PUSH_PROMISE"
            java.lang.String r6 = kotlin.text.D.o(r1, r6, r7, r3)
            goto L6a
        L4e:
            if (r6 != 0) goto L5d
            r6 = r7 & 32
            if (r6 == 0) goto L5d
            java.lang.String r6 = "PRIORITY"
            java.lang.String r7 = "COMPRESSED"
            java.lang.String r6 = kotlin.text.D.o(r1, r6, r7, r3)
            goto L6a
        L5d:
            r6 = r1
            goto L6a
        L5f:
            r6 = 1
            if (r7 != r6) goto L65
            java.lang.String r6 = "ACK"
            goto L6a
        L65:
            r6 = r2[r7]
            goto L6a
        L68:
            r6 = r2[r7]
        L6a:
            if (r8 == 0) goto L6f
            java.lang.String r7 = "<<"
            goto L71
        L6f:
            java.lang.String r7 = ">>"
        L71:
            java.lang.Integer r4 = java.lang.Integer.valueOf(r4)
            java.lang.Integer r5 = java.lang.Integer.valueOf(r5)
            java.lang.Object[] r4 = new java.lang.Object[]{r7, r4, r5, r0, r6}
            java.lang.String r5 = "%s 0x%08x %5d %-13s %s"
            java.lang.String r4 = okhttp3.internal.b.j(r5, r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.e.a(int, int, int, int, boolean):java.lang.String");
    }
}

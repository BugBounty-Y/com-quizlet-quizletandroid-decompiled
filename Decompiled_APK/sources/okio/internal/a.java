package okio.internal;

import java.io.EOFException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import okio.B;
import okio.C5091h;

/* loaded from: classes3.dex */
public abstract class a {
    public static final byte[] a;
    public static final long[] b;

    static {
        Intrinsics.checkNotNullParameter("0123456789abcdef", "<this>");
        byte[] bytes = "0123456789abcdef".getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        a = bytes;
        b = new long[]{-1, 9, 99, 999, 9999, 99999, 999999, 9999999, 99999999, 999999999, 9999999999L, 99999999999L, 999999999999L, 9999999999999L, 99999999999999L, 999999999999999L, 9999999999999999L, 99999999999999999L, 999999999999999999L, Long.MAX_VALUE};
    }

    public static final boolean a(B segment, int i, byte[] bytes, int i2) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        int i3 = segment.c;
        byte[] bArr = segment.a;
        for (int i4 = 1; i4 < i2; i4++) {
            if (i == i3) {
                segment = segment.f;
                Intrinsics.d(segment);
                i = segment.b;
                i3 = segment.c;
                bArr = segment.a;
            }
            if (bArr[i] != bytes[i4]) {
                return false;
            }
            i++;
        }
        return true;
    }

    public static final String b(C5091h c5091h, long j) throws EOFException {
        Intrinsics.checkNotNullParameter(c5091h, "<this>");
        if (j > 0) {
            long j2 = j - 1;
            if (c5091h.p(j2) == 13) {
                String strC0 = c5091h.c0(j2, Charsets.UTF_8);
                c5091h.skip(2L);
                return strC0;
            }
        }
        c5091h.getClass();
        String strC02 = c5091h.c0(j, Charsets.UTF_8);
        c5091h.skip(1L);
        return strC02;
    }

    /* JADX WARN: Code restructure failed: missing block: B:27:0x0061, code lost:
    
        if (r18 == false) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0063, code lost:
    
        return -2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0086, code lost:
    
        return r9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int c(okio.C5091h r16, okio.w r17, boolean r18) {
        /*
            Method dump skipped, instructions count: 176
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.internal.a.c(okio.h, okio.w, boolean):int");
    }
}

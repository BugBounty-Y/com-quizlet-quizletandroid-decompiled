package org.jsoup.nodes;

import java.nio.charset.Charset;
import java.util.HashMap;

/* loaded from: classes3.dex */
public abstract class k {
    public static final char[] a = {',', ';'};
    public static final HashMap b = new HashMap();

    static {
        j jVar = j.xhtml;
        Charset charset = org.jsoup.helper.a.a;
        new ThreadLocal();
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(java.lang.Appendable r4, org.jsoup.nodes.j r5, int r6) throws java.io.IOException {
        /*
            int[] r0 = r5.c
            int r0 = java.util.Arrays.binarySearch(r0, r6)
            java.lang.String r1 = ""
            if (r0 < 0) goto L1f
            java.lang.String[] r2 = r5.d
            int r3 = r2.length
            int r3 = r3 + (-1)
            if (r0 >= r3) goto L1c
            int[] r5 = r5.c
            int r3 = r0 + 1
            r5 = r5[r3]
            if (r5 != r6) goto L1c
            r5 = r2[r3]
            goto L20
        L1c:
            r5 = r2[r0]
            goto L20
        L1f:
            r5 = r1
        L20:
            boolean r0 = r1.equals(r5)
            r1 = 59
            if (r0 != 0) goto L36
            r6 = 38
            java.lang.Appendable r4 = r4.append(r6)
            java.lang.Appendable r4 = r4.append(r5)
            r4.append(r1)
            return
        L36:
            java.lang.String r5 = "&#x"
            java.lang.Appendable r4 = r4.append(r5)
            java.lang.String r5 = java.lang.Integer.toHexString(r6)
            java.lang.Appendable r4 = r4.append(r5)
            r4.append(r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.nodes.k.a(java.lang.Appendable, org.jsoup.nodes.j, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00e1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void b(java.lang.Appendable r16, java.lang.String r17, org.jsoup.nodes.f r18, boolean r19, boolean r20, boolean r21, boolean r22) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.nodes.k.b(java.lang.Appendable, java.lang.String, org.jsoup.nodes.f, boolean, boolean, boolean, boolean):void");
    }
}

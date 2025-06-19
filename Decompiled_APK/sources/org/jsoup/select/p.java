package org.jsoup.select;

/* loaded from: classes3.dex */
public final class p extends r {
    public final com.quizlet.data.repository.folderwithcreator.e b;

    public p(m mVar) {
        this.a = mVar;
        this.b = new com.quizlet.data.repository.folderwithcreator.e(mVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0040  */
    @Override // org.jsoup.select.m
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(org.jsoup.nodes.i r11, org.jsoup.nodes.i r12) {
        /*
            r10 = this;
            r11 = 0
            r0 = r11
        L2:
            java.util.List r1 = r12.f
            int r1 = r1.size()
            if (r0 >= r1) goto L93
            java.util.List r1 = r12.m()
            java.lang.Object r1 = r1.get(r0)
            org.jsoup.nodes.n r1 = (org.jsoup.nodes.n) r1
            boolean r2 = r1 instanceof org.jsoup.nodes.i
            if (r2 == 0) goto L8f
            org.jsoup.nodes.i r1 = (org.jsoup.nodes.i) r1
            com.quizlet.data.repository.folderwithcreator.e r2 = r10.b
            r2.b = r12
            r3 = 0
            r2.c = r3
            r4 = r11
            r3 = r1
        L23:
            r5 = 1
            if (r3 == 0) goto L88
            boolean r6 = r3 instanceof org.jsoup.nodes.i
            r7 = 5
            if (r6 == 0) goto L40
            r6 = r3
            org.jsoup.nodes.i r6 = (org.jsoup.nodes.i) r6
            java.lang.Object r8 = r2.d
            org.jsoup.select.m r8 = (org.jsoup.select.m) r8
            java.lang.Object r9 = r2.b
            org.jsoup.nodes.i r9 = (org.jsoup.nodes.i) r9
            boolean r8 = r8.a(r9, r6)
            if (r8 == 0) goto L40
            r2.c = r6
            r6 = r7
            goto L41
        L40:
            r6 = r5
        L41:
            if (r6 != r7) goto L44
            goto L88
        L44:
            if (r6 != r5) goto L59
            int r7 = r3.g()
            if (r7 <= 0) goto L59
            java.util.List r3 = r3.m()
            java.lang.Object r3 = r3.get(r11)
            org.jsoup.nodes.n r3 = (org.jsoup.nodes.n) r3
            int r4 = r4 + 1
            goto L23
        L59:
            org.jsoup.nodes.n r7 = r3.q()
            r8 = 4
            r9 = 2
            if (r7 != 0) goto L75
            if (r4 > 0) goto L64
            goto L75
        L64:
            if (r6 == r5) goto L68
            if (r6 != r9) goto L69
        L68:
            r6 = r5
        L69:
            org.jsoup.nodes.n r7 = r3.a
            int r4 = r4 + (-1)
            if (r6 != r8) goto L72
            r3.y()
        L72:
            r6 = r5
            r3 = r7
            goto L59
        L75:
            if (r6 == r5) goto L79
            if (r6 != r9) goto L7a
        L79:
            r6 = r5
        L7a:
            if (r3 != r1) goto L7d
            goto L88
        L7d:
            org.jsoup.nodes.n r5 = r3.q()
            if (r6 != r8) goto L86
            r3.y()
        L86:
            r3 = r5
            goto L23
        L88:
            java.lang.Object r1 = r2.c
            org.jsoup.nodes.i r1 = (org.jsoup.nodes.i) r1
            if (r1 == 0) goto L8f
            return r5
        L8f:
            int r0 = r0 + 1
            goto L2
        L93:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.select.p.a(org.jsoup.nodes.i, org.jsoup.nodes.i):boolean");
    }

    public final String toString() {
        return String.format(":has(%s)", this.a);
    }
}

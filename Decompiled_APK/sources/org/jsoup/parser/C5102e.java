package org.jsoup.parser;

/* renamed from: org.jsoup.parser.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5102e extends B {
    public C5102e() {
        super("InColumnGroup", 11);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:40:0x007f  */
    @Override // org.jsoup.parser.B
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean c(androidx.sqlite.db.b r11, org.jsoup.parser.C5096b r12) {
        /*
            r10 = this;
            r0 = 0
            java.lang.String r1 = "template"
            java.lang.String r2 = "html"
            r3 = 2
            boolean r4 = org.jsoup.parser.B.a(r11)
            r5 = 1
            if (r4 == 0) goto L13
            org.jsoup.parser.G r11 = (org.jsoup.parser.G) r11
            r12.z(r11)
            return r5
        L13:
            int r4 = r11.b
            int r4 = androidx.camera.camera2.internal.AbstractC0147y.k(r4)
            if (r4 == 0) goto Lb5
            org.jsoup.parser.u r6 = org.jsoup.parser.B.d
            if (r4 == r5) goto L6f
            if (r4 == r3) goto L3e
            r0 = 3
            if (r4 == r0) goto L38
            r0 = 5
            if (r4 == r0) goto L2c
            boolean r11 = r10.d(r11, r12)
            return r11
        L2c:
            boolean r0 = r12.b(r2)
            if (r0 == 0) goto L33
            return r5
        L33:
            boolean r11 = r10.d(r11, r12)
            return r11
        L38:
            org.jsoup.parser.H r11 = (org.jsoup.parser.H) r11
            r12.A(r11)
            return r5
        L3e:
            r2 = r11
            org.jsoup.parser.K r2 = (org.jsoup.parser.K) r2
            java.lang.String r2 = r2.d
            r2.getClass()
            boolean r1 = r2.equals(r1)
            if (r1 != 0) goto L6b
            java.lang.String r1 = "colgroup"
            boolean r1 = r2.equals(r1)
            if (r1 != 0) goto L59
            boolean r11 = r10.d(r11, r12)
            return r11
        L59:
            boolean r11 = r12.b(r2)
            if (r11 != 0) goto L63
            r12.o(r10)
            return r0
        L63:
            r12.H()
            org.jsoup.parser.z r11 = org.jsoup.parser.B.i
            r12.l = r11
            return r5
        L6b:
            r12.K(r11, r6)
            return r5
        L6f:
            r4 = r11
            org.jsoup.parser.L r4 = (org.jsoup.parser.L) r4
            java.lang.String r7 = r4.d
            r7.getClass()
            r8 = -1
            int r9 = r7.hashCode()
            switch(r9) {
                case -1321546630: goto L95;
                case 98688: goto L8a;
                case 3213227: goto L81;
                default: goto L7f;
            }
        L7f:
            r0 = r8
            goto L9c
        L81:
            boolean r0 = r7.equals(r2)
            if (r0 != 0) goto L88
            goto L7f
        L88:
            r0 = r3
            goto L9c
        L8a:
            java.lang.String r0 = "col"
            boolean r0 = r7.equals(r0)
            if (r0 != 0) goto L93
            goto L7f
        L93:
            r0 = r5
            goto L9c
        L95:
            boolean r1 = r7.equals(r1)
            if (r1 != 0) goto L9c
            goto L7f
        L9c:
            switch(r0) {
                case 0: goto Lb1;
                case 1: goto Lad;
                case 2: goto La4;
                default: goto L9f;
            }
        L9f:
            boolean r11 = r10.d(r11, r12)
            return r11
        La4:
            org.jsoup.parser.x r0 = org.jsoup.parser.B.g
            r12.g = r11
            boolean r11 = r0.c(r11, r12)
            return r11
        Lad:
            r12.B(r4)
            return r5
        Lb1:
            r12.K(r11, r6)
            return r5
        Lb5:
            r12.o(r10)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.parser.C5102e.c(androidx.sqlite.db.b, org.jsoup.parser.b):boolean");
    }

    public final boolean d(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (!c5096b.b("colgroup")) {
            c5096b.o(this);
            return false;
        }
        c5096b.H();
        c5096b.l = B.i;
        c5096b.e(bVar);
        return true;
    }
}

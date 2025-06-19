package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum Z0 extends e1 {
    public Z0() {
        super("CdataSection", 66);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        String strC;
        int iV = c5094a.v("]]>");
        if (iV != -1) {
            strC = C5094a.c(c5094a.a, c5094a.h, c5094a.e, iV);
            c5094a.e += iV;
        } else {
            int i = c5094a.c;
            int i2 = c5094a.e;
            if (i - i2 < 3) {
                c5094a.b();
                char[] cArr = c5094a.a;
                String[] strArr = c5094a.h;
                int i3 = c5094a.e;
                strC = C5094a.c(cArr, strArr, i3, c5094a.c - i3);
                c5094a.e = c5094a.c;
            } else {
                int i4 = i - 2;
                strC = C5094a.c(c5094a.a, c5094a.h, i2, i4 - i2);
                c5094a.e = i4;
            }
        }
        n.h.append(strC);
        if (c5094a.p("]]>") || c5094a.n()) {
            String string = n.h.toString();
            F f = new F();
            f.c = string;
            n.f(f);
            n.o(e1.a);
        }
    }
}

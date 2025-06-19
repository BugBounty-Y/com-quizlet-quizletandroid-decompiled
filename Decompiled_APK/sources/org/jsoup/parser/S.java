package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum S extends e1 {
    public S() {
        super("RCDATAEndTagName", 12);
    }

    public static void e(N n, C5094a c5094a) {
        n.g("</");
        n.h(n.h);
        c5094a.y();
        n.o(e1.c);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (c5094a.t()) {
            String strH = c5094a.h();
            n.k.y(strH);
            n.h.append(strH);
            return;
        }
        char cE = c5094a.e();
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            if (n.n()) {
                n.o(e1.H);
                return;
            } else {
                e(n, c5094a);
                return;
            }
        }
        if (cE == '/') {
            if (n.n()) {
                n.o(e1.X);
                return;
            } else {
                e(n, c5094a);
                return;
            }
        }
        if (cE != '>') {
            e(n, c5094a);
        } else if (!n.n()) {
            e(n, c5094a);
        } else {
            n.k();
            n.o(e1.a);
        }
    }
}

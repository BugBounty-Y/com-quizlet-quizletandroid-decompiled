package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum L0 extends e1 {
    public L0() {
        super("AfterDoctypeName", 53);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        boolean zN = c5094a.n();
        Z z = e1.a;
        if (zN) {
            n.l(this);
            n.m.g = true;
            n.j();
            n.o(z);
            return;
        }
        if (c5094a.s('\t', '\n', '\r', '\f', ' ')) {
            c5094a.a();
            return;
        }
        if (c5094a.r('>')) {
            n.j();
            n.o(z);
            n.a.a();
        } else if (c5094a.q("PUBLIC")) {
            n.m.d = "PUBLIC";
            n.o(e1.m1);
        } else if (c5094a.q("SYSTEM")) {
            n.m.d = "SYSTEM";
            n.o(e1.s1);
        } else {
            n.m(this);
            n.m.g = true;
            n.o(e1.x1);
            n.a.a();
        }
    }
}

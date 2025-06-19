package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum I0 extends e1 {
    public I0() {
        super("Doctype", 50);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        J0 j0 = e1.j1;
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            n.o(j0);
            return;
        }
        if (cE != '>') {
            if (cE != 65535) {
                n.m(this);
                n.o(j0);
                return;
            }
            n.l(this);
        }
        n.m(this);
        n.m.q();
        n.m.g = true;
        n.j();
        n.o(e1.a);
    }
}

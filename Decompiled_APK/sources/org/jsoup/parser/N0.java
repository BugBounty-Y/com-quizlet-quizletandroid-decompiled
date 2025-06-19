package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum N0 extends e1 {
    public N0() {
        super("BeforeDoctypePublicIdentifier", 55);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            return;
        }
        if (cE == '\"') {
            n.o(e1.o1);
            return;
        }
        if (cE == '\'') {
            n.o(e1.p1);
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.m(this);
            n.m.g = true;
            n.j();
            n.o(z);
            return;
        }
        if (cE != 65535) {
            n.m(this);
            n.m.g = true;
            n.o(e1.x1);
        } else {
            n.l(this);
            n.m.g = true;
            n.j();
            n.o(z);
        }
    }
}

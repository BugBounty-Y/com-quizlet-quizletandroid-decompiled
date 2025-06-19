package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum X0 extends e1 {
    public X0() {
        super("AfterDoctypeSystemIdentifier", 64);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.j();
            n.o(z);
        } else if (cE != 65535) {
            n.m(this);
            n.o(e1.x1);
        } else {
            n.l(this);
            n.m.g = true;
            n.j();
            n.o(z);
        }
    }
}

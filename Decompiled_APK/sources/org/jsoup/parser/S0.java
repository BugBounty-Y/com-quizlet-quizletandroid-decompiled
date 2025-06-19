package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum S0 extends e1 {
    public S0() {
        super("BetweenDoctypePublicAndSystemIdentifiers", 59);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            return;
        }
        if (cE == '\"') {
            n.m(this);
            n.o(e1.u1);
            return;
        }
        if (cE == '\'') {
            n.m(this);
            n.o(e1.v1);
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.j();
            n.o(z);
        } else if (cE != 65535) {
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

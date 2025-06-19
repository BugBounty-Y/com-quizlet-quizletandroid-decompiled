package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum O0 extends e1 {
    public O0() {
        super("DoctypePublicIdentifier_doubleQuoted", 56);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        if (cE == 0) {
            n.m(this);
            n.m.e.append((char) 65533);
            return;
        }
        if (cE == '\"') {
            n.o(e1.q1);
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
            n.m.e.append(cE);
            return;
        }
        n.l(this);
        n.m.g = true;
        n.j();
        n.o(z);
    }
}

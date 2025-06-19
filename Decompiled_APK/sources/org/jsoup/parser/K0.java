package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum K0 extends e1 {
    public K0() {
        super("DoctypeName", 52);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (c5094a.u()) {
            n.m.c.append(c5094a.h());
            return;
        }
        char cE = c5094a.e();
        if (cE == 0) {
            n.m(this);
            n.m.c.append((char) 65533);
            return;
        }
        if (cE != ' ') {
            Z z = e1.a;
            if (cE == '>') {
                n.j();
                n.o(z);
                return;
            }
            if (cE == 65535) {
                n.l(this);
                n.m.g = true;
                n.j();
                n.o(z);
                return;
            }
            if (cE != '\t' && cE != '\n' && cE != '\f' && cE != '\r') {
                n.m.c.append(cE);
                return;
            }
        }
        n.o(e1.l1);
    }
}

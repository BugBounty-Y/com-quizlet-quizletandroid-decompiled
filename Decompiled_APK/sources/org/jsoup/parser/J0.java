package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum J0 extends e1 {
    public J0() {
        super("BeforeDoctypeName", 51);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        boolean zT = c5094a.t();
        K0 k0 = e1.k1;
        if (zT) {
            n.m.q();
            n.o(k0);
            return;
        }
        char cE = c5094a.e();
        if (cE == 0) {
            n.m(this);
            n.m.q();
            n.m.c.append((char) 65533);
            n.o(k0);
            return;
        }
        if (cE != ' ') {
            if (cE == 65535) {
                n.l(this);
                n.m.q();
                n.m.g = true;
                n.j();
                n.o(e1.a);
                return;
            }
            if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r') {
                return;
            }
            n.m.q();
            n.m.c.append(cE);
            n.o(k0);
        }
    }
}

package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum H0 extends e1 {
    public H0() {
        super("CommentEndBang", 49);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        D0 d0 = e1.e1;
        if (cE == 0) {
            n.m(this);
            H h = n.n;
            h.w("--!");
            h.v((char) 65533);
            n.o(d0);
            return;
        }
        if (cE == '-') {
            n.n.w("--!");
            n.o(e1.f1);
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.i();
            n.o(z);
        } else if (cE == 65535) {
            n.l(this);
            n.i();
            n.o(z);
        } else {
            H h2 = n.n;
            h2.w("--!");
            h2.v(cE);
            n.o(d0);
        }
    }
}

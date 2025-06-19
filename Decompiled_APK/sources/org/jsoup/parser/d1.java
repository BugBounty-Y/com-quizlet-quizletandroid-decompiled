package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum d1 extends e1 {
    public d1() {
        super("EndTagOpen", 8);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        boolean zN = c5094a.n();
        Z z = e1.a;
        if (zN) {
            n.l(this);
            n.g("</");
            n.o(z);
            return;
        }
        if (c5094a.t()) {
            n.c(false);
            n.o(e1.j);
            return;
        }
        if (c5094a.r('>')) {
            n.m(this);
            n.o(z);
            n.a.a();
        } else {
            n.m(this);
            H h = n.n;
            h.q();
            h.e = true;
            n.n.v('/');
            n.o(e1.Y);
        }
    }
}

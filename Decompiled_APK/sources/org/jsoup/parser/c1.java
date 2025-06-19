package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum c1 extends e1 {
    public c1() {
        super("TagOpen", 7);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == '!') {
            n.o(e1.Z);
            n.a.a();
            return;
        }
        if (cL == '/') {
            n.o(e1.i);
            n.a.a();
            return;
        }
        if (cL == '?') {
            H h = n.n;
            h.q();
            h.e = true;
            n.o(e1.Y);
            return;
        }
        if (c5094a.t()) {
            n.c(true);
            n.o(e1.j);
        } else {
            n.m(this);
            n.e('<');
            n.o(e1.a);
        }
    }
}

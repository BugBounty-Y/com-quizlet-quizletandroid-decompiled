package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum Q extends e1 {
    public Q() {
        super("RCDATAEndTagOpen", 11);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (!c5094a.t()) {
            n.g("</");
            n.o(e1.c);
            return;
        }
        n.c(false);
        M m = n.k;
        char cL = c5094a.l();
        m.getClass();
        m.y(String.valueOf(cL));
        n.h.append(c5094a.l());
        n.o(e1.m);
        n.a.a();
    }
}

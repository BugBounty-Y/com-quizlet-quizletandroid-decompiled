package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum Z extends e1 {
    public Z() {
        super("Data", 0);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            n.e(c5094a.e());
            return;
        }
        if (cL == '&') {
            n.o(e1.b);
            n.a.a();
        } else if (cL == '<') {
            n.o(e1.h);
            n.a.a();
        } else if (cL != 65535) {
            n.g(c5094a.g());
        } else {
            n.f(new J());
        }
    }
}

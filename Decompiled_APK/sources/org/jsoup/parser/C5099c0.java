package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.c0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5099c0 extends e1 {
    public C5099c0() {
        super("ScriptDataEscaped", 21);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (c5094a.n()) {
            n.l(this);
            n.o(e1.a);
            return;
        }
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            c5094a.a();
            n.e((char) 65533);
        } else if (cL == '-') {
            n.e('-');
            n.o(e1.w);
            n.a.a();
        } else if (cL != '<') {
            n.g(c5094a.j('-', '<', 0));
        } else {
            n.o(e1.y);
            n.a.a();
        }
    }
}

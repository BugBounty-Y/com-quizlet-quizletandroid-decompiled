package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.j0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5113j0 extends e1 {
    public C5113j0() {
        super("ScriptDataDoubleEscaped", 28);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            c5094a.a();
            n.e((char) 65533);
            return;
        }
        if (cL == '-') {
            n.e(cL);
            n.o(e1.D);
            n.a.a();
        } else if (cL == '<') {
            n.e(cL);
            n.o(e1.F);
            n.a.a();
        } else if (cL != 65535) {
            n.g(c5094a.j('-', '<', 0));
        } else {
            n.l(this);
            n.o(e1.a);
        }
    }
}

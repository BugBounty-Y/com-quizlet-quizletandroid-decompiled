package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.g0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5107g0 extends e1 {
    public C5107g0() {
        super("ScriptDataEscapedEndTagOpen", 25);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (!c5094a.t()) {
            n.g("</");
            n.o(e1.v);
            return;
        }
        n.c(false);
        M m = n.k;
        char cL = c5094a.l();
        m.getClass();
        m.y(String.valueOf(cL));
        n.h.append(c5094a.l());
        n.o(e1.A);
        n.a.a();
    }
}

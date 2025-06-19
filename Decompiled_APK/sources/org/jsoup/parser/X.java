package org.jsoup.parser;

/* loaded from: classes3.dex */
public enum X extends e1 {
    public X() {
        super("ScriptDataEndTagOpen", 17);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        Y y = e1.s;
        a1 a1Var = e1.f;
        if (c5094a.t()) {
            n.c(false);
            n.o(y);
        } else {
            n.g("</");
            n.o(a1Var);
        }
    }
}

package org.jsoup.parser;

/* loaded from: classes3.dex */
public enum A0 extends e1 {
    public A0() {
        super("MarkupDeclarationOpen", 43);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        if (c5094a.p("--")) {
            n.n.q();
            n.o(e1.c1);
            return;
        }
        if (c5094a.q("DOCTYPE")) {
            n.o(e1.i1);
            return;
        }
        if (c5094a.p("[CDATA[")) {
            n.d();
            n.o(e1.y1);
            return;
        }
        n.m(this);
        H h = n.n;
        h.q();
        h.e = true;
        n.o(e1.Y);
    }
}

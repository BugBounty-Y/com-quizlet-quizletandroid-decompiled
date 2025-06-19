package org.jsoup.parser;

/* renamed from: org.jsoup.parser.n0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5121n0 extends e1 {
    public C5121n0() {
        super("ScriptDataDoubleEscapedLessthanSign", 31);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        if (!c5094a.r('/')) {
            n.o(e1.C);
            return;
        }
        n.e('/');
        n.d();
        n.o(e1.G);
        n.a.a();
    }
}

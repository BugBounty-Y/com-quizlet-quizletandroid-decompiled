package org.jsoup.parser;

/* renamed from: org.jsoup.parser.b0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5097b0 extends e1 {
    public C5097b0() {
        super("ScriptDataEscapeStartDash", 20);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        if (!c5094a.r('-')) {
            n.o(e1.f);
            return;
        }
        n.e('-');
        n.o(e1.x);
        n.a.a();
    }
}

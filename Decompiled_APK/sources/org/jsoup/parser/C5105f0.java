package org.jsoup.parser;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* renamed from: org.jsoup.parser.f0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5105f0 extends e1 {
    public C5105f0() {
        super("ScriptDataEscapedLessthanSign", 24);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        if (c5094a.t()) {
            n.d();
            n.h.append(c5094a.l());
            n.g(SimpleComparison.LESS_THAN_OPERATION);
            n.e(c5094a.l());
            n.o(e1.B);
            n.a.a();
            return;
        }
        if (!c5094a.r('/')) {
            n.e('<');
            n.o(e1.v);
        } else {
            n.d();
            n.o(e1.z);
            n.a.a();
        }
    }
}

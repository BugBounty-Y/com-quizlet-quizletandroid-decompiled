package org.jsoup.parser;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.IOException;

/* loaded from: classes3.dex */
public enum W extends e1 {
    public W() {
        super("ScriptDataLessthanSign", 16);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        if (cE == '!') {
            n.g("<!");
            n.o(e1.t);
            return;
        }
        if (cE == '/') {
            n.d();
            n.o(e1.r);
        } else if (cE != 65535) {
            n.g(SimpleComparison.LESS_THAN_OPERATION);
            c5094a.y();
            n.o(e1.f);
        } else {
            n.g(SimpleComparison.LESS_THAN_OPERATION);
            n.l(this);
            n.o(e1.a);
        }
    }
}

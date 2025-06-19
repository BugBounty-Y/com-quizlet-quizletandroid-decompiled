package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum O extends e1 {
    public O() {
        super("TagName", 9);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char c;
        c5094a.b();
        int i = c5094a.e;
        int i2 = c5094a.c;
        char[] cArr = c5094a.a;
        int i3 = i;
        while (i3 < i2 && (c = cArr[i3]) != '\t' && c != '\n' && c != '\f' && c != '\r' && c != ' ' && c != '/' && c != '<' && c != '>') {
            i3++;
        }
        c5094a.e = i3;
        n.k.y(i3 > i ? C5094a.c(c5094a.a, c5094a.h, i, i3 - i) : "");
        char cE = c5094a.e();
        if (cE == 0) {
            n.k.y(e1.B1);
            return;
        }
        if (cE != ' ') {
            if (cE == '/') {
                n.o(e1.X);
                return;
            }
            Z z = e1.a;
            if (cE == '<') {
                c5094a.y();
                n.m(this);
            } else if (cE != '>') {
                if (cE == 65535) {
                    n.l(this);
                    n.o(z);
                    return;
                } else if (cE != '\t' && cE != '\n' && cE != '\f' && cE != '\r') {
                    M m = n.k;
                    m.getClass();
                    m.y(String.valueOf(cE));
                    return;
                }
            }
            n.k();
            n.o(z);
            return;
        }
        n.o(e1.H);
    }
}

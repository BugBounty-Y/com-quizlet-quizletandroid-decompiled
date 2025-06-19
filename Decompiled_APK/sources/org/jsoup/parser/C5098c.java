package org.jsoup.parser;

import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: org.jsoup.parser.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5098c extends B {
    public C5098c() {
        super("InTableText", 9);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.b == 5) {
            G g = (G) bVar;
            if (g.c.equals(B.x)) {
                c5096b.o(this);
                return false;
            }
            c5096b.t.add(g.c);
            return true;
        }
        if (c5096b.t.size() > 0) {
            Iterator it2 = c5096b.t.iterator();
            while (it2.hasNext()) {
                String str = (String) it2.next();
                if (org.jsoup.internal.a.d(str)) {
                    G g2 = new G();
                    g2.c = str;
                    c5096b.z(g2);
                } else {
                    c5096b.o(this);
                    boolean zC = org.jsoup.internal.a.c(c5096b.a().d.b, A.A);
                    B b = B.g;
                    if (zC) {
                        c5096b.w = true;
                        G g3 = new G();
                        g3.c = str;
                        c5096b.K(g3, b);
                        c5096b.w = false;
                    } else {
                        G g4 = new G();
                        g4.c = str;
                        c5096b.K(g4, b);
                    }
                }
            }
            c5096b.t = new ArrayList();
        }
        c5096b.l = c5096b.m;
        return c5096b.e(bVar);
    }
}

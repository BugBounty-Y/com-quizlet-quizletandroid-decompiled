package org.jsoup.parser;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;

/* renamed from: org.jsoup.parser.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5143z extends B {
    public C5143z() {
        super("InTable", 8);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.b == 5 && org.jsoup.internal.a.c(c5096b.a().d.b, A.A)) {
            c5096b.t = new ArrayList();
            c5096b.m = c5096b.l;
            c5096b.l = B.j;
            return c5096b.e(bVar);
        }
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        if (bVar.h()) {
            c5096b.o(this);
            return false;
        }
        boolean zK = bVar.k();
        C5133u c5133u = B.d;
        if (!zK) {
            if (!bVar.j()) {
                if (!bVar.i()) {
                    d(bVar, c5096b);
                    return true;
                }
                if (c5096b.b("html")) {
                    c5096b.o(this);
                }
                return true;
            }
            String str = ((K) bVar).d;
            if (str.equals("table")) {
                if (!c5096b.x(str)) {
                    c5096b.o(this);
                    return false;
                }
                c5096b.I("table");
                c5096b.P();
                return true;
            }
            if (org.jsoup.internal.a.c(str, A.z)) {
                c5096b.o(this);
                return false;
            }
            if (str.equals("template")) {
                c5096b.K(bVar, c5133u);
                return true;
            }
            d(bVar, c5096b);
            return true;
        }
        L l = (L) bVar;
        String str2 = l.d;
        if (str2.equals("caption")) {
            c5096b.n();
            c5096b.r.add(null);
            c5096b.y(l);
            c5096b.l = B.k;
            return true;
        }
        if (str2.equals("colgroup")) {
            c5096b.n();
            c5096b.y(l);
            c5096b.l = B.l;
            return true;
        }
        if (str2.equals("col")) {
            c5096b.n();
            c5096b.g("colgroup");
            return c5096b.e(bVar);
        }
        if (org.jsoup.internal.a.c(str2, A.s)) {
            c5096b.n();
            c5096b.y(l);
            c5096b.l = B.m;
            return true;
        }
        if (org.jsoup.internal.a.c(str2, A.t)) {
            c5096b.n();
            c5096b.g("tbody");
            return c5096b.e(bVar);
        }
        if (str2.equals("table")) {
            c5096b.o(this);
            if (c5096b.x(str2)) {
                c5096b.I(str2);
                if (c5096b.P()) {
                    return c5096b.e(bVar);
                }
                c5096b.y(l);
                return true;
            }
        } else {
            if (org.jsoup.internal.a.c(str2, A.u)) {
                c5096b.g = bVar;
                return c5133u.c(bVar, c5096b);
            }
            if (str2.equals("input")) {
                if (l.z() && l.m.i(DBUserFields.Names.USER_UPGRADE_TYPE).equalsIgnoreCase("hidden")) {
                    c5096b.B(l);
                    return true;
                }
                d(bVar, c5096b);
                return true;
            }
            if (!str2.equals("form")) {
                d(bVar, c5096b);
                return true;
            }
            c5096b.o(this);
            if (c5096b.p == null && !c5096b.F("template")) {
                c5096b.C(l, false, false);
                return true;
            }
        }
        return false;
    }

    public final void d(androidx.sqlite.db.b bVar, C5096b c5096b) {
        c5096b.o(this);
        c5096b.w = true;
        c5096b.K(bVar, B.g);
        c5096b.w = false;
    }
}

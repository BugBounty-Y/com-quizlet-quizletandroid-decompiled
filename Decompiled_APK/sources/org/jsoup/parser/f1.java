package org.jsoup.parser;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public abstract class f1 {
    public com.quizlet.data.repository.course.membership.c a;
    public C5094a b;
    public N c;
    public org.jsoup.nodes.g d;
    public ArrayList e;
    public String f;
    public androidx.sqlite.db.b g;
    public D h;
    public HashMap i;
    public final L j = new L();
    public final K k = new K();

    public final org.jsoup.nodes.i a() {
        int size = this.e.size();
        return size > 0 ? (org.jsoup.nodes.i) this.e.get(size - 1) : this.d;
    }

    public final boolean b(String str) {
        org.jsoup.nodes.i iVarA;
        return (this.e.size() == 0 || (iVarA = a()) == null || !iVarA.d.b.equals(str)) ? false : true;
    }

    public abstract D c();

    public void d(StringReader stringReader, String str, com.quizlet.data.repository.course.membership.c cVar) {
        if (str == null) {
            throw new ValidationException("The parameter 'baseUri' must not be null.");
        }
        org.jsoup.helper.b.g(cVar);
        org.jsoup.nodes.g gVar = new org.jsoup.nodes.g(str);
        this.d = gVar;
        gVar.k = cVar;
        this.a = cVar;
        this.h = (D) cVar.c;
        C5094a c5094a = new C5094a(stringReader, 32768);
        this.b = c5094a;
        C c = (C) cVar.b;
        c.getClass();
        c5094a.i = null;
        this.g = null;
        this.c = new N(this.b, c);
        this.e = new ArrayList(32);
        this.i = new HashMap();
        this.f = str;
    }

    public abstract boolean e(androidx.sqlite.db.b bVar);

    public final boolean f(String str) {
        androidx.sqlite.db.b bVar = this.g;
        K k = this.k;
        if (bVar == k) {
            K k2 = new K();
            k2.B(str);
            return e(k2);
        }
        k.q();
        k.B(str);
        return e(k);
    }

    public final void g(String str) {
        androidx.sqlite.db.b bVar = this.g;
        L l = this.j;
        if (bVar == l) {
            L l2 = new L();
            l2.B(str);
            e(l2);
        } else {
            l.q();
            l.B(str);
            e(l);
        }
    }

    public final void h() {
        androidx.sqlite.db.b bVar;
        N n = this.c;
        while (true) {
            if (n.e) {
                StringBuilder sb = n.g;
                int length = sb.length();
                G g = n.l;
                if (length != 0) {
                    String string = sb.toString();
                    sb.delete(0, sb.length());
                    g.c = string;
                    n.f = null;
                    bVar = g;
                } else {
                    String str = n.f;
                    if (str != null) {
                        g.c = str;
                        n.f = null;
                        bVar = g;
                    } else {
                        n.e = false;
                        bVar = n.d;
                    }
                }
                e(bVar);
                bVar.q();
                if (bVar.b == 6) {
                    return;
                }
            } else {
                n.c.d(n, n.a);
            }
        }
    }

    public final E i(String str, D d) {
        E e = (E) this.i.get(str);
        if (e != null) {
            return e;
        }
        E eC = E.c(str, d);
        this.i.put(str, eC);
        return eC;
    }
}

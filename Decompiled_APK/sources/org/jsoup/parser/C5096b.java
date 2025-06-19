package org.jsoup.parser;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.io.StringReader;
import java.util.ArrayList;
import org.jsoup.helper.ValidationException;

/* renamed from: org.jsoup.parser.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5096b extends f1 {
    public B l;
    public B m;
    public boolean n;
    public org.jsoup.nodes.i o;
    public org.jsoup.nodes.l p;
    public org.jsoup.nodes.i q;
    public ArrayList r;
    public ArrayList s;
    public ArrayList t;
    public K u;
    public boolean v;
    public boolean w;
    public boolean x;
    public final String[] y = {null};
    public static final String[] z = {"applet", "caption", "html", "marquee", "object", "table", "td", "th"};
    public static final String[] A = {"ol", "ul"};
    public static final String[] B = {"button"};
    public static final String[] C = {"html", "table"};
    public static final String[] D = {"optgroup", "option"};
    public static final String[] E = {"dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt", "rtc"};
    public static final String[] F = {"caption", "colgroup", "dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt", "rtc", "tbody", "td", "tfoot", "th", "thead", "tr"};
    public static final String[] G = {"address", "applet", "area", "article", "aside", "base", "basefont", "bgsound", "blockquote", "body", "br", "button", "caption", "center", "col", "colgroup", "command", "dd", "details", "dir", "div", "dl", "dt", "embed", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe", "img", "input", "isindex", "li", "link", "listing", "marquee", "menu", "meta", "nav", "noembed", "noframes", "noscript", "object", "ol", "p", "param", "plaintext", "pre", "script", "section", "select", "style", OTUXParamsKeys.OT_UX_SUMMARY, "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "title", "tr", "ul", "wbr", "xmp"};

    public static boolean G(ArrayList arrayList, org.jsoup.nodes.i iVar) {
        int size = arrayList.size();
        int i = size - 1;
        int i2 = i >= 256 ? size - 257 : 0;
        while (i >= i2) {
            if (((org.jsoup.nodes.i) arrayList.get(i)) == iVar) {
                return true;
            }
            i--;
        }
        return false;
    }

    public final void A(H h) {
        String string = h.d;
        if (string == null) {
            string = h.c.toString();
        }
        E(new org.jsoup.nodes.d(string));
    }

    public final org.jsoup.nodes.i B(L l) {
        E eI = i(l.A(), this.h);
        D d = this.h;
        org.jsoup.nodes.b bVar = l.m;
        d.a(bVar);
        org.jsoup.nodes.i iVar = new org.jsoup.nodes.i(eI, null, bVar);
        E(iVar);
        if (l.l) {
            if (!E.j.containsKey(eI.a)) {
                eI.f = true;
            } else if (!eI.e) {
                N n = this.c;
                Object[] objArr = {eI.b};
                C c = n.b;
                if (c.b()) {
                    c.add(new io.ktor.utils.io.A(n.a, "Tag [%s] cannot be self closing; not a void tag", objArr));
                    return iVar;
                }
            }
        }
        return iVar;
    }

    public final void C(L l, boolean z2, boolean z3) {
        E eI = i(l.A(), this.h);
        D d = this.h;
        org.jsoup.nodes.b bVar = l.m;
        d.a(bVar);
        org.jsoup.nodes.l lVar = new org.jsoup.nodes.l(eI, bVar);
        if (!z3 || !F("template")) {
            this.p = lVar;
        }
        E(lVar);
        if (z2) {
            this.e.add(lVar);
        }
    }

    public final void D(org.jsoup.nodes.n nVar) {
        org.jsoup.nodes.i iVarJ;
        org.jsoup.nodes.i iVarS = s("table");
        boolean z2 = false;
        if (iVarS != null) {
            iVarJ = (org.jsoup.nodes.i) iVarS.a;
            if (iVarJ != null) {
                z2 = true;
            } else {
                iVarJ = j(iVarS);
            }
        } else {
            iVarJ = (org.jsoup.nodes.i) this.e.get(0);
        }
        if (!z2) {
            iVarJ.B(nVar);
            return;
        }
        org.jsoup.helper.b.g(iVarS);
        org.jsoup.helper.b.g(iVarS.a);
        iVarS.a.c(iVarS.b, nVar);
    }

    public final void E(org.jsoup.nodes.n nVar) {
        org.jsoup.nodes.l lVar;
        if (this.e.isEmpty()) {
            this.d.B(nVar);
        } else if (this.w && org.jsoup.internal.a.c(a().d.b, A.A)) {
            D(nVar);
        } else {
            a().B(nVar);
        }
        if (nVar instanceof org.jsoup.nodes.i) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) nVar;
            if (!iVar.d.h || (lVar = this.p) == null) {
                return;
            }
            lVar.j.add(iVar);
        }
    }

    public final boolean F(String str) {
        return s(str) != null;
    }

    public final void H() {
    }

    public final void I(String str) {
        for (int size = this.e.size() - 1; size >= 0; size--) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) this.e.get(size);
            this.e.remove(size);
            if (iVar.d.b.equals(str)) {
                boolean z2 = this.g instanceof K;
                return;
            }
        }
    }

    public final void J() {
        if (this.s.size() > 0) {
        }
    }

    public final boolean K(androidx.sqlite.db.b bVar, B b) {
        this.g = bVar;
        return b.c(bVar, this);
    }

    public final void L(B b) {
        this.s.add(b);
    }

    public final void M() {
        if (this.e.size() > 256) {
            return;
        }
        boolean z2 = true;
        org.jsoup.nodes.i iVar = this.r.size() > 0 ? (org.jsoup.nodes.i) android.support.v4.media.session.a.e(1, this.r) : null;
        if (iVar == null || G(this.e, iVar)) {
            return;
        }
        int size = this.r.size();
        int i = size - 12;
        if (i < 0) {
            i = 0;
        }
        int i2 = size - 1;
        int i3 = i2;
        while (i3 != i) {
            i3--;
            iVar = (org.jsoup.nodes.i) this.r.get(i3);
            if (iVar == null || G(this.e, iVar)) {
                z2 = false;
                break;
            }
        }
        while (true) {
            if (!z2) {
                i3++;
                iVar = (org.jsoup.nodes.i) this.r.get(i3);
            }
            org.jsoup.helper.b.g(iVar);
            org.jsoup.nodes.i iVar2 = new org.jsoup.nodes.i(i(iVar.d.b, this.h), null, iVar.e().clone());
            E(iVar2);
            this.e.add(iVar2);
            this.r.set(i3, iVar2);
            if (i3 == i2) {
                return;
            } else {
                z2 = false;
            }
        }
    }

    public final void N(org.jsoup.nodes.i iVar) {
        for (int size = this.r.size() - 1; size >= 0; size--) {
            if (((org.jsoup.nodes.i) this.r.get(size)) == iVar) {
                this.r.remove(size);
                return;
            }
        }
    }

    public final void O(org.jsoup.nodes.i iVar) {
        for (int size = this.e.size() - 1; size >= 0; size--) {
            if (((org.jsoup.nodes.i) this.e.get(size)) == iVar) {
                this.e.remove(size);
                return;
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0106 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:119:0x010c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0112 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0117 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:122:0x012a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x012f A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0145 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:125:0x014a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:126:0x014f A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x016e A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0134  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x013b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean P() {
        /*
            Method dump skipped, instructions count: 472
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.parser.C5096b.P():boolean");
    }

    @Override // org.jsoup.parser.f1
    public final D c() {
        return D.c;
    }

    @Override // org.jsoup.parser.f1
    public final void d(StringReader stringReader, String str, com.quizlet.data.repository.course.membership.c cVar) {
        super.d(stringReader, str, cVar);
        this.l = B.a;
        this.m = null;
        this.n = false;
        this.o = null;
        this.p = null;
        this.q = null;
        this.r = new ArrayList();
        this.s = new ArrayList();
        this.t = new ArrayList();
        this.u = new K();
        this.v = true;
        this.w = false;
        this.x = false;
    }

    @Override // org.jsoup.parser.f1
    public final boolean e(androidx.sqlite.db.b bVar) {
        this.g = bVar;
        return this.l.c(bVar, this);
    }

    public final org.jsoup.nodes.i j(org.jsoup.nodes.i iVar) {
        for (int size = this.e.size() - 1; size >= 0; size--) {
            if (((org.jsoup.nodes.i) this.e.get(size)) == iVar) {
                return (org.jsoup.nodes.i) this.e.get(size - 1);
            }
        }
        return null;
    }

    public final void k(org.jsoup.nodes.i iVar) {
        int size = this.r.size();
        int i = size - 13;
        int i2 = 0;
        if (i < 0) {
            i = 0;
        }
        for (int i3 = size - 1; i3 >= i; i3--) {
            org.jsoup.nodes.i iVar2 = (org.jsoup.nodes.i) this.r.get(i3);
            if (iVar2 == null) {
                return;
            }
            if (iVar.d.b.equals(iVar2.d.b) && iVar.e().equals(iVar2.e())) {
                i2++;
            }
            if (i2 == 3) {
                this.r.remove(i3);
                return;
            }
        }
    }

    public final void l() {
        while (!this.r.isEmpty()) {
            int size = this.r.size();
            if ((size > 0 ? (org.jsoup.nodes.i) this.r.remove(size - 1) : null) == null) {
                return;
            }
        }
    }

    public final void m(String... strArr) {
        for (int size = this.e.size() - 1; size >= 0; size--) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) this.e.get(size);
            String str = iVar.d.b;
            String[] strArr2 = org.jsoup.internal.a.a;
            for (String str2 : strArr) {
                if (str2.equals(str)) {
                    return;
                }
            }
            if (iVar.d.b.equals("html")) {
                return;
            }
            this.e.remove(size);
        }
    }

    public final void n() {
        m("table", "template");
    }

    public final void o(B b) {
        if (((C) this.a.b).b()) {
            ((C) this.a.b).add(new io.ktor.utils.io.A(this.b, "Unexpected %s token [%s] when in state [%s]", new Object[]{this.g.getClass().getSimpleName(), this.g, b}));
        }
    }

    public final void p(String str) {
        while (org.jsoup.internal.a.c(a().d.b, E)) {
            if (str != null && b(str)) {
                return;
            } else {
                H();
            }
        }
    }

    public final void q(boolean z2) {
        String[] strArr = z2 ? F : E;
        while (org.jsoup.internal.a.c(a().d.b, strArr)) {
            H();
        }
    }

    public final org.jsoup.nodes.i r(String str) {
        for (int size = this.r.size() - 1; size >= 0; size--) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) this.r.get(size);
            if (iVar == null) {
                return null;
            }
            if (iVar.d.b.equals(str)) {
                return iVar;
            }
        }
        return null;
    }

    public final org.jsoup.nodes.i s(String str) {
        int size = this.e.size();
        int i = size - 1;
        int i2 = i >= 256 ? size - 257 : 0;
        while (i >= i2) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) this.e.get(i);
            if (iVar.d.b.equals(str)) {
                return iVar;
            }
            i--;
        }
        return null;
    }

    public final boolean t(String str) {
        String[] strArr = B;
        String[] strArr2 = z;
        String[] strArr3 = this.y;
        strArr3[0] = str;
        return w(strArr3, strArr2, strArr);
    }

    public final String toString() {
        return "TreeBuilder{currentToken=" + this.g + ", state=" + this.l + ", currentElement=" + a() + '}';
    }

    public final boolean u(String str) {
        String[] strArr = z;
        String[] strArr2 = this.y;
        strArr2[0] = str;
        return w(strArr2, strArr, null);
    }

    public final boolean v(String str) {
        for (int size = this.e.size() - 1; size >= 0; size--) {
            String str2 = ((org.jsoup.nodes.i) this.e.get(size)).d.b;
            if (str2.equals(str)) {
                return true;
            }
            if (!org.jsoup.internal.a.c(str2, D)) {
                return false;
            }
        }
        throw new ValidationException("Should not be reachable");
    }

    public final boolean w(String[] strArr, String[] strArr2, String[] strArr3) {
        int size = this.e.size();
        int i = size - 1;
        int i2 = i > 100 ? size - 101 : 0;
        while (i >= i2) {
            String str = ((org.jsoup.nodes.i) this.e.get(i)).d.b;
            if (!org.jsoup.internal.a.c(str, strArr)) {
                if (org.jsoup.internal.a.c(str, strArr2) || (strArr3 != null && org.jsoup.internal.a.c(str, strArr3))) {
                    break;
                }
                i--;
            } else {
                return true;
            }
        }
        return false;
    }

    public final boolean x(String str) {
        String[] strArr = C;
        String[] strArr2 = this.y;
        strArr2[0] = str;
        return w(strArr2, strArr, null);
    }

    public final org.jsoup.nodes.i y(L l) {
        if (l.z()) {
            org.jsoup.nodes.b bVar = l.m;
            if (bVar.a != 0 && bVar.h(this.h) > 0) {
                Object[] objArr = {l.d};
                C c = (C) this.a.b;
                if (c.b()) {
                    c.add(new io.ktor.utils.io.A(this.b, "Dropped duplicate attribute(s) in tag [%s]", objArr));
                }
            }
        }
        if (!l.l) {
            E eI = i(l.A(), this.h);
            D d = this.h;
            org.jsoup.nodes.b bVar2 = l.m;
            d.a(bVar2);
            org.jsoup.nodes.i iVar = new org.jsoup.nodes.i(eI, null, bVar2);
            E(iVar);
            this.e.add(iVar);
            return iVar;
        }
        org.jsoup.nodes.i iVarB = B(l);
        this.e.add(iVarB);
        this.c.o(e1.a);
        N n = this.c;
        K k = this.u;
        k.q();
        k.B(iVarB.d.a);
        n.f(k);
        return iVarB;
    }

    public final void z(G g) {
        org.jsoup.nodes.m eVar;
        org.jsoup.nodes.i iVarA = a();
        String str = iVarA.d.b;
        String str2 = g.c;
        if (g instanceof F) {
            eVar = new org.jsoup.nodes.c(str2);
        } else if (str.equals("script") || str.equals("style")) {
            eVar = new org.jsoup.nodes.e();
            eVar.d = str2;
        } else {
            eVar = new org.jsoup.nodes.p(str2);
        }
        iVarA.B(eVar);
    }
}

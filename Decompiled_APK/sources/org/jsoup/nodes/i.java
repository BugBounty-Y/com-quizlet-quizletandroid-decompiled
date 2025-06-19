package org.jsoup.nodes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.jsoup.helper.ValidationException;
import org.jsoup.parser.C;
import org.jsoup.parser.D;
import org.jsoup.parser.E;

/* loaded from: classes3.dex */
public class i extends n {
    public static final List h = Collections.EMPTY_LIST;
    public static final String i;
    public final E d;
    public WeakReference e;
    public List f;
    public b g;

    static {
        Pattern.compile("\\s+");
        i = "/".concat("baseUri");
    }

    public i(E e, String str, b bVar) {
        org.jsoup.helper.b.g(e);
        this.f = n.c;
        this.g = bVar;
        this.d = e;
        if (str != null) {
            J(str);
        }
    }

    public static void E(n nVar, StringBuilder sb) {
        if (nVar instanceof p) {
            sb.append(((p) nVar).D());
        } else if ((nVar instanceof i) && ((i) nVar).d.b.equals("br")) {
            sb.append("\n");
        }
    }

    public static boolean P(n nVar) {
        if (nVar instanceof i) {
            i iVar = (i) nVar;
            int i2 = 0;
            while (!iVar.d.g) {
                iVar = (i) iVar.a;
                i2++;
                if (i2 >= 6 || iVar == null) {
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [org.jsoup.nodes.n] */
    @Override // org.jsoup.nodes.n
    public final n A() {
        i iVar = this;
        while (true) {
            ?? r1 = iVar.a;
            if (r1 == 0) {
                return iVar;
            }
            iVar = r1;
        }
    }

    public final void B(n nVar) {
        org.jsoup.helper.b.g(nVar);
        n nVar2 = nVar.a;
        if (nVar2 != null) {
            nVar2.z(nVar);
        }
        nVar.a = this;
        m();
        this.f.add(nVar);
        nVar.b = this.f.size() - 1;
    }

    public final i D(String str) {
        i iVar = new i(E.c(str, (D) AbstractC3390s2.c(this).c), f(), null);
        B(iVar);
        return iVar;
    }

    public final List F() {
        List list;
        if (this.f.size() == 0) {
            return h;
        }
        WeakReference weakReference = this.e;
        if (weakReference != null && (list = (List) weakReference.get()) != null) {
            return list;
        }
        int size = this.f.size();
        ArrayList arrayList = new ArrayList(size);
        for (int i2 = 0; i2 < size; i2++) {
            n nVar = (n) this.f.get(i2);
            if (nVar instanceof i) {
                arrayList.add((i) nVar);
            }
        }
        this.e = new WeakReference(arrayList);
        return arrayList;
    }

    public final C G() {
        return new C(F());
    }

    @Override // org.jsoup.nodes.n
    /* renamed from: H, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public i i() {
        return (i) super.i();
    }

    public final String I() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        for (n nVar : this.f) {
            if (nVar instanceof e) {
                sbB.append(((e) nVar).D());
            } else if (nVar instanceof d) {
                sbB.append(((d) nVar).D());
            } else if (nVar instanceof i) {
                sbB.append(((i) nVar).I());
            } else if (nVar instanceof c) {
                sbB.append(((c) nVar).D());
            }
        }
        return org.jsoup.internal.a.g(sbB);
    }

    public final void J(String str) {
        e().s(i, str);
    }

    public final int K() {
        i iVar = (i) this.a;
        if (iVar == null) {
            return 0;
        }
        List listF = iVar.F();
        int size = listF.size();
        for (int i2 = 0; i2 < size; i2++) {
            if (listF.get(i2) == this) {
                return i2;
            }
        }
        return 0;
    }

    public final boolean L() {
        for (n nVar : this.f) {
            if (nVar instanceof p) {
                if (!org.jsoup.internal.a.d(((p) nVar).D())) {
                    return true;
                }
            } else if ((nVar instanceof i) && ((i) nVar).L()) {
                return true;
            }
        }
        return false;
    }

    public final String M() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        int size = this.f.size();
        for (int i2 = 0; i2 < size; i2++) {
            n nVar = (n) this.f.get(i2);
            g gVarV = nVar.v();
            if (gVarV == null) {
                gVarV = new g("");
            }
            AbstractC3394t2.j(new com.quizlet.remote.model.user.emailconfirmation.c(sbB, gVarV.j), nVar);
        }
        String strG = org.jsoup.internal.a.g(sbB);
        g gVarV2 = v();
        if (gVarV2 == null) {
            gVarV2 = new g("");
        }
        return gVarV2.j.e ? strG.trim() : strG;
    }

    public final void N(List list) {
        if (list == null) {
            throw new ValidationException("Children collection to be inserted must not be null.");
        }
        int size = this.f.size();
        if (!(size >= 0)) {
            throw new ValidationException("Insert position out of bounds.");
        }
        c(size, (n[]) new ArrayList(list).toArray(new n[0]));
    }

    public final String O() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        for (int i2 = 0; i2 < this.f.size(); i2++) {
            n nVar = (n) this.f.get(i2);
            if (nVar instanceof p) {
                p pVar = (p) nVar;
                String strD = pVar.D();
                if (P(pVar.a) || (pVar instanceof c)) {
                    sbB.append(strD);
                } else {
                    org.jsoup.internal.a.a(strD, sbB, p.G(sbB));
                }
            } else if ((nVar instanceof i) && ((i) nVar).d.b.equals("br") && !p.G(sbB)) {
                sbB.append(" ");
            }
        }
        return org.jsoup.internal.a.g(sbB).trim();
    }

    public final i R() {
        n nVar = this.a;
        if (nVar == null) {
            return null;
        }
        List listF = ((i) nVar).F();
        int size = listF.size();
        int i2 = 0;
        int i3 = 0;
        while (true) {
            if (i3 >= size) {
                break;
            }
            if (listF.get(i3) == this) {
                i2 = i3;
                break;
            }
            i3++;
        }
        if (i2 > 0) {
            return (i) listF.get(i2 - 1);
        }
        return null;
    }

    public final C S(String str) {
        org.jsoup.helper.b.e(str);
        org.jsoup.select.m mVarJ = org.jsoup.select.o.j(str);
        org.jsoup.helper.b.g(mVarJ);
        C c = new C(1);
        AbstractC3394t2.j(new com.quizlet.data.repository.folderset.c(this, c, mVarJ, 19), this);
        return c;
    }

    public final boolean T(f fVar) {
        i iVar;
        if (!fVar.e) {
            return false;
        }
        E e = this.d;
        if (!e.d && ((iVar = (i) this.a) == null || !iVar.d.d)) {
            return false;
        }
        if (!e.c) {
            n nVar = this.a;
            i iVar2 = (i) nVar;
            if (iVar2 == null || iVar2.d.c) {
                n nVar2 = null;
                if (nVar != null && this.b > 0) {
                    nVar2 = (n) nVar.m().get(this.b - 1);
                }
                if (nVar2 != null) {
                    return false;
                }
            }
        }
        return true;
    }

    public final String U() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        int size = this.f.size();
        for (int i2 = 0; i2 < size; i2++) {
            E((n) this.f.get(i2), sbB);
        }
        return org.jsoup.internal.a.g(sbB);
    }

    @Override // org.jsoup.nodes.n
    public final b e() {
        if (this.g == null) {
            this.g = new b();
        }
        return this.g;
    }

    @Override // org.jsoup.nodes.n
    public final String f() {
        for (i iVar = this; iVar != null; iVar = (i) iVar.a) {
            b bVar = iVar.g;
            if (bVar != null) {
                String str = i;
                if (bVar.n(str) != -1) {
                    return iVar.g.i(str);
                }
            }
        }
        return "";
    }

    @Override // org.jsoup.nodes.n
    public final int g() {
        return this.f.size();
    }

    @Override // org.jsoup.nodes.n
    public final n k(n nVar) {
        i iVar = (i) super.k(nVar);
        b bVar = this.g;
        iVar.g = bVar != null ? bVar.clone() : null;
        curtains.internal.a aVar = new curtains.internal.a(iVar, this.f.size());
        iVar.f = aVar;
        aVar.addAll(this.f);
        return iVar;
    }

    @Override // org.jsoup.nodes.n
    public final n l() {
        this.f.clear();
        return this;
    }

    @Override // org.jsoup.nodes.n
    public final List m() {
        if (this.f == n.c) {
            this.f = new curtains.internal.a(this, 4);
        }
        return this.f;
    }

    @Override // org.jsoup.nodes.n
    public final boolean o() {
        return this.g != null;
    }

    @Override // org.jsoup.nodes.n
    public String r() {
        return this.d.a;
    }

    @Override // org.jsoup.nodes.n
    public void t(StringBuilder sb, int i2, f fVar) throws IOException {
        if (T(fVar) && (sb == null || sb.length() > 0)) {
            n.p(sb, i2, fVar);
        }
        Appendable appendableAppend = sb.append('<');
        E e = this.d;
        appendableAppend.append(e.a);
        b bVar = this.g;
        if (bVar != null) {
            bVar.m(sb, fVar);
        }
        if (this.f.isEmpty()) {
            boolean z = e.e;
            if (z || e.f) {
                if (fVar.h == 1 && z) {
                    sb.append('>');
                    return;
                } else {
                    sb.append(" />");
                    return;
                }
            }
        }
        sb.append('>');
    }

    @Override // org.jsoup.nodes.n
    public void u(StringBuilder sb, int i2, f fVar) throws IOException {
        boolean zIsEmpty = this.f.isEmpty();
        E e = this.d;
        if (zIsEmpty && (e.e || e.f)) {
            return;
        }
        if (fVar.e && !this.f.isEmpty() && e.d) {
            n.p(sb, i2, fVar);
        }
        sb.append("</").append(e.a).append('>');
    }

    @Override // org.jsoup.nodes.n
    public final n w() {
        return (i) this.a;
    }
}

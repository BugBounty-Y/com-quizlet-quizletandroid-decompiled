package androidx.constraintlayout.core.parser;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes.dex */
public abstract class b extends c {
    public ArrayList e;

    public b(char[] cArr) {
        super(cArr);
        this.e = new ArrayList();
    }

    public final ArrayList A() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            c cVar = (c) it2.next();
            if (cVar instanceof d) {
                arrayList.add(((d) cVar).c());
            }
        }
        return arrayList;
    }

    public final void B(String str, b bVar) {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            d dVar = (d) ((c) it2.next());
            if (dVar.c().equals(str)) {
                if (dVar.e.size() > 0) {
                    dVar.e.set(0, bVar);
                    return;
                } else {
                    dVar.e.add(bVar);
                    return;
                }
            }
        }
        d dVar2 = new d(str.toCharArray());
        dVar2.b = 0L;
        long length = str.length() - 1;
        if (dVar2.c == Long.MAX_VALUE) {
            dVar2.c = length;
            b bVar2 = dVar2.d;
            if (bVar2 != null) {
                bVar2.i(dVar2);
            }
        }
        if (dVar2.e.size() > 0) {
            dVar2.e.set(0, bVar);
        } else {
            dVar2.e.add(bVar);
        }
        this.e.add(dVar2);
    }

    @Override // androidx.constraintlayout.core.parser.c
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return this.e.equals(((b) obj).e);
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public int hashCode() {
        return Objects.hash(this.e, Integer.valueOf(super.hashCode()));
    }

    public final void i(c cVar) {
        this.e.add(cVar);
    }

    @Override // androidx.constraintlayout.core.parser.c
    /* renamed from: k, reason: merged with bridge method [inline-methods] */
    public b clone() {
        b bVar = (b) super.clone();
        ArrayList arrayList = new ArrayList(this.e.size());
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            c cVarClone = ((c) it2.next()).clone();
            cVarClone.d = bVar;
            arrayList.add(cVarClone);
        }
        bVar.e = arrayList;
        return bVar;
    }

    public final c m(int i) throws CLParsingException {
        if (i < 0 || i >= this.e.size()) {
            throw new CLParsingException(android.support.v4.media.session.a.f(i, "no element at index "), this);
        }
        return (c) this.e.get(i);
    }

    public final c n(String str) throws CLParsingException {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            d dVar = (d) ((c) it2.next());
            if (dVar.c().equals(str)) {
                if (dVar.e.size() > 0) {
                    return (c) dVar.e.get(0);
                }
                return null;
            }
        }
        throw new CLParsingException(android.support.v4.media.session.a.B("no element for key <", str, SimpleComparison.GREATER_THAN_OPERATION), this);
    }

    public final float o(int i) throws CLParsingException {
        c cVarM = m(i);
        if (cVarM != null) {
            return cVarM.e();
        }
        throw new CLParsingException(android.support.v4.media.session.a.f(i, "no float at index "), this);
    }

    public final float r(String str) throws CLParsingException {
        c cVarN = n(str);
        if (cVarN != null) {
            return cVarN.e();
        }
        StringBuilder sbY = android.support.v4.media.session.a.y("no float found for key <", str, ">, found [");
        sbY.append(cVarN.h());
        sbY.append("] : ");
        sbY.append(cVarN);
        throw new CLParsingException(sbY.toString(), this);
    }

    public final int s(int i) throws CLParsingException {
        c cVarM = m(i);
        if (cVarM != null) {
            return cVarM.g();
        }
        throw new CLParsingException(android.support.v4.media.session.a.f(i, "no int at index "), this);
    }

    public final c t(int i) {
        if (i < 0 || i >= this.e.size()) {
            return null;
        }
        return (c) this.e.get(i);
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final String toString() {
        StringBuilder sb = new StringBuilder();
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            c cVar = (c) it2.next();
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(cVar);
        }
        return super.toString() + " = <" + ((Object) sb) + " >";
    }

    public final c u(String str) {
        Iterator it2 = this.e.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            d dVar = (d) ((c) it2.next());
            if (dVar.c().equals(str)) {
                if (dVar.e.size() > 0) {
                    return (c) dVar.e.get(0);
                }
            }
        }
        return null;
    }

    public final String v(int i) throws CLParsingException {
        c cVarM = m(i);
        if (cVarM instanceof h) {
            return cVarM.c();
        }
        throw new CLParsingException(android.support.v4.media.session.a.f(i, "no string at index "), this);
    }

    public final String w(String str) throws CLParsingException {
        c cVarN = n(str);
        if (cVarN instanceof h) {
            return cVarN.c();
        }
        StringBuilder sbH = AbstractC0147y.h("no string found for key <", str, ">, found [", cVarN != null ? cVarN.h() : null, "] : ");
        sbH.append(cVarN);
        throw new CLParsingException(sbH.toString(), this);
    }

    public final String x(String str) {
        c cVarU = u(str);
        if (cVarU instanceof h) {
            return cVarU.c();
        }
        return null;
    }

    public final boolean z(String str) {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            c cVar = (c) it2.next();
            if ((cVar instanceof d) && ((d) cVar).c().equals(str)) {
                return true;
            }
        }
        return false;
    }
}

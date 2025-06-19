package androidx.constraintlayout.core.widgets.analyzer;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class d extends p {
    public final ArrayList k;
    public int l;

    public d(androidx.constraintlayout.core.widgets.e eVar, int i) {
        androidx.constraintlayout.core.widgets.e eVar2;
        super(eVar);
        this.k = new ArrayList();
        this.f = i;
        androidx.constraintlayout.core.widgets.e eVar3 = this.b;
        androidx.constraintlayout.core.widgets.e eVarN = eVar3.n(i);
        while (true) {
            androidx.constraintlayout.core.widgets.e eVar4 = eVarN;
            eVar2 = eVar3;
            eVar3 = eVar4;
            if (eVar3 == null) {
                break;
            } else {
                eVarN = eVar3.n(this.f);
            }
        }
        this.b = eVar2;
        int i2 = this.f;
        p pVar = i2 == 0 ? eVar2.d : i2 == 1 ? eVar2.e : null;
        ArrayList arrayList = this.k;
        arrayList.add(pVar);
        androidx.constraintlayout.core.widgets.e eVarM = eVar2.m(this.f);
        while (eVarM != null) {
            int i3 = this.f;
            arrayList.add(i3 == 0 ? eVarM.d : i3 == 1 ? eVarM.e : null);
            eVarM = eVarM.m(this.f);
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            p pVar2 = (p) it2.next();
            int i4 = this.f;
            if (i4 == 0) {
                pVar2.b.b = this;
            } else if (i4 == 1) {
                pVar2.b.c = this;
            }
        }
        if (this.f == 0 && ((androidx.constraintlayout.core.widgets.f) this.b.W).y0 && arrayList.size() > 1) {
            this.b = ((p) android.support.v4.media.session.a.e(1, arrayList)).b;
        }
        this.l = this.f == 0 ? this.b.m0 : this.b.n0;
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x015b  */
    @Override // androidx.constraintlayout.core.widgets.analyzer.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.constraintlayout.core.widgets.analyzer.e r30) {
        /*
            Method dump skipped, instructions count: 961
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.analyzer.d.a(androidx.constraintlayout.core.widgets.analyzer.e):void");
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void d() {
        ArrayList arrayList = this.k;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((p) it2.next()).d();
        }
        int size = arrayList.size();
        if (size < 1) {
            return;
        }
        androidx.constraintlayout.core.widgets.e eVar = ((p) arrayList.get(0)).b;
        androidx.constraintlayout.core.widgets.e eVar2 = ((p) arrayList.get(size - 1)).b;
        int i = this.f;
        g gVar = this.i;
        g gVar2 = this.h;
        if (i == 0) {
            androidx.constraintlayout.core.widgets.c cVar = eVar.K;
            androidx.constraintlayout.core.widgets.c cVar2 = eVar2.M;
            g gVarI = p.i(cVar, 0);
            int iE = cVar.e();
            androidx.constraintlayout.core.widgets.e eVarM = m();
            if (eVarM != null) {
                iE = eVarM.K.e();
            }
            if (gVarI != null) {
                p.b(gVar2, gVarI, iE);
            }
            g gVarI2 = p.i(cVar2, 0);
            int iE2 = cVar2.e();
            androidx.constraintlayout.core.widgets.e eVarN = n();
            if (eVarN != null) {
                iE2 = eVarN.M.e();
            }
            if (gVarI2 != null) {
                p.b(gVar, gVarI2, -iE2);
            }
        } else {
            androidx.constraintlayout.core.widgets.c cVar3 = eVar.L;
            androidx.constraintlayout.core.widgets.c cVar4 = eVar2.N;
            g gVarI3 = p.i(cVar3, 1);
            int iE3 = cVar3.e();
            androidx.constraintlayout.core.widgets.e eVarM2 = m();
            if (eVarM2 != null) {
                iE3 = eVarM2.L.e();
            }
            if (gVarI3 != null) {
                p.b(gVar2, gVarI3, iE3);
            }
            g gVarI4 = p.i(cVar4, 1);
            int iE4 = cVar4.e();
            androidx.constraintlayout.core.widgets.e eVarN2 = n();
            if (eVarN2 != null) {
                iE4 = eVarN2.N.e();
            }
            if (gVarI4 != null) {
                p.b(gVar, gVarI4, -iE4);
            }
        }
        gVar2.a = this;
        gVar.a = this;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void e() {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.k;
            if (i >= arrayList.size()) {
                return;
            }
            ((p) arrayList.get(i)).e();
            i++;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final void f() {
        this.c = null;
        Iterator it2 = this.k.iterator();
        while (it2.hasNext()) {
            ((p) it2.next()).f();
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final long j() {
        ArrayList arrayList = this.k;
        int size = arrayList.size();
        long j = 0;
        for (int i = 0; i < size; i++) {
            j = r5.i.f + ((p) arrayList.get(i)).j() + j + r5.h.f;
        }
        return j;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.p
    public final boolean k() {
        ArrayList arrayList = this.k;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (!((p) arrayList.get(i)).k()) {
                return false;
            }
        }
        return true;
    }

    public final androidx.constraintlayout.core.widgets.e m() {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.k;
            if (i >= arrayList.size()) {
                return null;
            }
            androidx.constraintlayout.core.widgets.e eVar = ((p) arrayList.get(i)).b;
            if (eVar.j0 != 8) {
                return eVar;
            }
            i++;
        }
    }

    public final androidx.constraintlayout.core.widgets.e n() {
        ArrayList arrayList = this.k;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            androidx.constraintlayout.core.widgets.e eVar = ((p) arrayList.get(size)).b;
            if (eVar.j0 != 8) {
                return eVar;
            }
        }
        return null;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ChainRun ");
        sb.append(this.f == 0 ? "horizontal : " : "vertical : ");
        Iterator it2 = this.k.iterator();
        while (it2.hasNext()) {
            p pVar = (p) it2.next();
            sb.append(SimpleComparison.LESS_THAN_OPERATION);
            sb.append(pVar);
            sb.append("> ");
        }
        return sb.toString();
    }
}

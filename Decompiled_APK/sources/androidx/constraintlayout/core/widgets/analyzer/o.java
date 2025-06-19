package androidx.constraintlayout.core.widgets.analyzer;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class o {
    public static int f;
    public ArrayList a;
    public int b;
    public int c;
    public ArrayList d;
    public int e;

    public final void a(ArrayList arrayList) {
        int size = this.a.size();
        if (this.e != -1 && size > 0) {
            for (int i = 0; i < arrayList.size(); i++) {
                o oVar = (o) arrayList.get(i);
                if (this.e == oVar.b) {
                    c(this.c, oVar);
                }
            }
        }
        if (size == 0) {
            arrayList.remove(this);
        }
    }

    public final int b(androidx.constraintlayout.core.c cVar, int i) {
        int iN;
        int iN2;
        ArrayList arrayList = this.a;
        if (arrayList.size() == 0) {
            return 0;
        }
        androidx.constraintlayout.core.widgets.f fVar = (androidx.constraintlayout.core.widgets.f) ((androidx.constraintlayout.core.widgets.e) arrayList.get(0)).W;
        cVar.t();
        fVar.c(cVar, false);
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            ((androidx.constraintlayout.core.widgets.e) arrayList.get(i2)).c(cVar, false);
        }
        if (i == 0 && fVar.C0 > 0) {
            androidx.constraintlayout.core.widgets.k.a(fVar, cVar, arrayList, 0);
        }
        if (i == 1 && fVar.D0 > 0) {
            androidx.constraintlayout.core.widgets.k.a(fVar, cVar, arrayList, 1);
        }
        try {
            cVar.p();
        } catch (Exception e) {
            System.err.println(e.toString() + "\n" + Arrays.toString(e.getStackTrace()).replace("[", "   at ").replace(",", "\n   at").replace("]", ""));
        }
        this.d = new ArrayList();
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) arrayList.get(i3);
            com.google.firebase.perf.logging.b bVar = new com.google.firebase.perf.logging.b(3);
            new WeakReference(eVar);
            androidx.constraintlayout.core.c.n(eVar.K);
            androidx.constraintlayout.core.c.n(eVar.L);
            androidx.constraintlayout.core.c.n(eVar.M);
            androidx.constraintlayout.core.c.n(eVar.N);
            androidx.constraintlayout.core.c.n(eVar.O);
            this.d.add(bVar);
        }
        if (i == 0) {
            iN = androidx.constraintlayout.core.c.n(fVar.K);
            iN2 = androidx.constraintlayout.core.c.n(fVar.M);
            cVar.t();
        } else {
            iN = androidx.constraintlayout.core.c.n(fVar.L);
            iN2 = androidx.constraintlayout.core.c.n(fVar.N);
            cVar.t();
        }
        return iN2 - iN;
    }

    public final void c(int i, o oVar) {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            ArrayList arrayList = oVar.a;
            if (!arrayList.contains(eVar)) {
                arrayList.add(eVar);
            }
            int i2 = oVar.b;
            if (i == 0) {
                eVar.r0 = i2;
            } else {
                eVar.s0 = i2;
            }
        }
        this.e = oVar.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        int i = this.c;
        sb.append(i == 0 ? "Horizontal" : i == 1 ? "Vertical" : i == 2 ? "Both" : "Unknown");
        sb.append(" [");
        String strR = android.support.v4.media.session.a.r(sb, this.b, "] <");
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) it2.next();
            StringBuilder sbX = android.support.v4.media.session.a.x(strR, " ");
            sbX.append(eVar.l0);
            strR = sbX.toString();
        }
        return android.support.v4.media.session.a.k(strR, " >");
    }
}

package androidx.work.impl;

import androidx.work.C1422c;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public abstract class i {
    public static final /* synthetic */ int a = 0;

    static {
        androidx.work.z.e("Schedulers");
    }

    public static void a(androidx.work.impl.model.t tVar, androidx.work.B b, ArrayList arrayList) {
        if (arrayList.size() > 0) {
            b.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                tVar.q(jCurrentTimeMillis, ((androidx.work.impl.model.q) it2.next()).a);
            }
        }
    }

    public static void b(C1422c c1422c, WorkDatabase workDatabase, List list) {
        if (list == null || list.size() == 0) {
            return;
        }
        androidx.work.impl.model.t tVarU = workDatabase.u();
        workDatabase.c();
        try {
            ArrayList arrayListJ = tVarU.j();
            a(tVarU, c1422c.d, arrayListJ);
            ArrayList arrayListI = tVarU.i(c1422c.k);
            a(tVarU, c1422c.d, arrayListI);
            arrayListI.addAll(arrayListJ);
            ArrayList arrayListG = tVarU.g();
            workDatabase.p();
            workDatabase.k();
            if (arrayListI.size() > 0) {
                androidx.work.impl.model.q[] qVarArr = (androidx.work.impl.model.q[]) arrayListI.toArray(new androidx.work.impl.model.q[arrayListI.size()]);
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    InterfaceC1435g interfaceC1435g = (InterfaceC1435g) it2.next();
                    if (interfaceC1435g.c()) {
                        interfaceC1435g.a(qVarArr);
                    }
                }
            }
            if (arrayListG.size() > 0) {
                androidx.work.impl.model.q[] qVarArr2 = (androidx.work.impl.model.q[]) arrayListG.toArray(new androidx.work.impl.model.q[arrayListG.size()]);
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    InterfaceC1435g interfaceC1435g2 = (InterfaceC1435g) it3.next();
                    if (!interfaceC1435g2.c()) {
                        interfaceC1435g2.a(qVarArr2);
                    }
                }
            }
        } catch (Throwable th) {
            workDatabase.k();
            throw th;
        }
    }
}

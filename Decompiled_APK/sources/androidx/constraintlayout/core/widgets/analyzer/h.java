package androidx.constraintlayout.core.widgets.analyzer;

import java.util.Iterator;

/* loaded from: classes.dex */
public class h extends g {
    public int m;

    public h(p pVar) {
        super(pVar);
        if (pVar instanceof l) {
            this.e = 2;
        } else {
            this.e = 3;
        }
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.g
    public final void d(int i) {
        if (this.j) {
            return;
        }
        this.j = true;
        this.g = i;
        Iterator it2 = this.k.iterator();
        while (it2.hasNext()) {
            e eVar = (e) it2.next();
            eVar.a(eVar);
        }
    }
}

package org.jsoup.nodes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import java.util.HashMap;
import java.util.Iterator;
import org.jsoup.parser.C5096b;
import org.jsoup.parser.E;

/* loaded from: classes3.dex */
public final class g extends i {
    public f j;
    public com.quizlet.data.repository.course.membership.c k;
    public int l;

    public g(String str) {
        HashMap map = E.j;
        E e = (E) map.get("#root");
        if (e == null) {
            String strC = AbstractC3386r2.c("#root");
            org.jsoup.helper.b.e(strC);
            e = (E) map.get(AbstractC3386r2.c(strC));
            if (e == null) {
                e = new E(strC);
                e.c = false;
            }
        }
        super(e, str, null);
        this.j = new f();
        this.l = 1;
        this.k = new com.quizlet.data.repository.course.membership.c(new C5096b());
    }

    @Override // org.jsoup.nodes.i
    /* renamed from: H */
    public final i clone() {
        g gVar = (g) super.clone();
        gVar.j = this.j.clone();
        return gVar;
    }

    public final i V() {
        i iVarD;
        Iterator it2 = F().iterator();
        while (true) {
            if (!it2.hasNext()) {
                iVarD = D("html");
                break;
            }
            iVarD = (i) it2.next();
            if (iVarD.d.b.equals("html")) {
                break;
            }
        }
        for (i iVar : iVarD.F()) {
            if ("body".equals(iVar.d.b) || "frameset".equals(iVar.d.b)) {
                return iVar;
            }
        }
        return iVarD.D("body");
    }

    @Override // org.jsoup.nodes.i, org.jsoup.nodes.n
    /* renamed from: clone */
    public final Object i() {
        g gVar = (g) super.clone();
        gVar.j = this.j.clone();
        return gVar;
    }

    @Override // org.jsoup.nodes.i, org.jsoup.nodes.n
    public final n i() {
        g gVar = (g) super.clone();
        gVar.j = this.j.clone();
        return gVar;
    }

    @Override // org.jsoup.nodes.i, org.jsoup.nodes.n
    public final String r() {
        return "#document";
    }

    @Override // org.jsoup.nodes.n
    public final String s() {
        return M();
    }
}

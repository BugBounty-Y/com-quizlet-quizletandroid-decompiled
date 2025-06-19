package org.jsoup.select;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.jsoup.parser.C;
import org.jsoup.parser.E;

/* loaded from: classes3.dex */
public final class d extends m {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        C c;
        switch (this.a) {
            case 0:
                return true;
            case 1:
                for (org.jsoup.nodes.n nVar : iVar2.h()) {
                    if (!(nVar instanceof org.jsoup.nodes.d) && !(nVar instanceof org.jsoup.nodes.q) && !(nVar instanceof org.jsoup.nodes.h)) {
                        return false;
                    }
                }
                return true;
            case 2:
                org.jsoup.nodes.i iVar3 = (org.jsoup.nodes.i) iVar2.a;
                return (iVar3 == null || (iVar3 instanceof org.jsoup.nodes.g) || iVar2.K() != 0) ? false : true;
            case 3:
                org.jsoup.nodes.i iVar4 = (org.jsoup.nodes.i) iVar2.a;
                return (iVar4 == null || (iVar4 instanceof org.jsoup.nodes.g) || iVar2.K() != iVar4.G().size() - 1) ? false : true;
            case 4:
                org.jsoup.nodes.n nVar2 = iVar2.a;
                org.jsoup.nodes.i iVar5 = (org.jsoup.nodes.i) nVar2;
                if (iVar5 == null || (iVar5 instanceof org.jsoup.nodes.g)) {
                    return false;
                }
                if (nVar2 == null) {
                    c = new C(0, 1);
                } else {
                    List<org.jsoup.nodes.i> listF = ((org.jsoup.nodes.i) nVar2).F();
                    C c2 = new C(listF.size() - 1, 1);
                    for (org.jsoup.nodes.i iVar6 : listF) {
                        if (iVar6 != iVar2) {
                            c2.add(iVar6);
                        }
                    }
                    c = c2;
                }
                return c.isEmpty();
            case 5:
                org.jsoup.nodes.i iVar7 = (org.jsoup.nodes.i) iVar2.a;
                if (iVar7 == null || (iVar7 instanceof org.jsoup.nodes.g)) {
                    return false;
                }
                Iterator<E> it2 = iVar7.G().iterator();
                int i = 0;
                while (it2.hasNext()) {
                    if (((org.jsoup.nodes.i) it2.next()).d.equals(iVar2.d)) {
                        i++;
                    }
                }
                return i == 1;
            case 6:
                if (iVar instanceof org.jsoup.nodes.g) {
                    iVar = (org.jsoup.nodes.i) iVar.F().get(0);
                }
                return iVar2 == iVar;
            case 7:
                if (iVar2 instanceof org.jsoup.nodes.o) {
                    return true;
                }
                iVar2.getClass();
                ArrayList arrayList = new ArrayList();
                for (org.jsoup.nodes.n nVar3 : iVar2.f) {
                    if (nVar3 instanceof org.jsoup.nodes.p) {
                        arrayList.add((org.jsoup.nodes.p) nVar3);
                    }
                }
                Iterator it3 = Collections.unmodifiableList(arrayList).iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        return false;
                    }
                    org.jsoup.nodes.p pVar = (org.jsoup.nodes.p) it3.next();
                    String str = iVar2.d.a;
                    org.jsoup.helper.b.g(str);
                    HashMap map = E.j;
                    E eClone = (E) map.get(str);
                    if (eClone == null) {
                        String strTrim = str.trim();
                        org.jsoup.helper.b.e(strTrim);
                        String strC = AbstractC3386r2.c(strTrim);
                        E e = (E) map.get(strC);
                        if (e == null) {
                            eClone = new E(strTrim);
                            eClone.c = false;
                        } else if (strTrim.equals(strC)) {
                            eClone = e;
                        } else {
                            eClone = e.clone();
                            eClone.a = strTrim;
                        }
                    }
                    org.jsoup.nodes.o oVar = new org.jsoup.nodes.o(eClone, iVar2.f(), iVar2.e());
                    pVar.getClass();
                    org.jsoup.helper.b.g(pVar.a);
                    org.jsoup.nodes.n nVar4 = pVar.a;
                    nVar4.getClass();
                    org.jsoup.helper.b.d(pVar.a == nVar4);
                    org.jsoup.nodes.n nVar5 = oVar.a;
                    if (nVar5 != null) {
                        nVar5.z(oVar);
                    }
                    int i2 = pVar.b;
                    nVar4.m().set(i2, oVar);
                    oVar.a = nVar4;
                    oVar.b = i2;
                    pVar.a = null;
                    oVar.B(pVar);
                }
            default:
                return iVar == iVar2;
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "*";
            case 1:
                return ":empty";
            case 2:
                return ":first-child";
            case 3:
                return ":last-child";
            case 4:
                return ":only-child";
            case 5:
                return ":only-of-type";
            case 6:
                return ":root";
            case 7:
                return ":matchText";
            default:
                return super.toString();
        }
    }
}

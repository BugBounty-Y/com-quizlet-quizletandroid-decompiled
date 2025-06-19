package org.jsoup.select;

import java.util.Iterator;
import org.jsoup.parser.C;

/* loaded from: classes3.dex */
public class k extends m {
    public final int a;
    public final int b;
    public final /* synthetic */ int c;

    public k(int i, int i2, int i3) {
        this.c = i3;
        this.a = i;
        this.b = i2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        int iK;
        org.jsoup.nodes.i iVar3 = (org.jsoup.nodes.i) iVar2.a;
        if (iVar3 == null || (iVar3 instanceof org.jsoup.nodes.g)) {
            return false;
        }
        switch (this.c) {
            case 0:
                iK = iVar2.K() + 1;
                break;
            case 1:
                org.jsoup.nodes.i iVar4 = (org.jsoup.nodes.i) iVar2.a;
                iK = iVar4 == null ? 0 : iVar4.G().size() - iVar2.K();
                break;
            case 2:
                org.jsoup.nodes.i iVar5 = (org.jsoup.nodes.i) iVar2.a;
                iK = 0;
                if (iVar5 != null) {
                    C cG = iVar5.G();
                    for (int iK2 = iVar2.K(); iK2 < cG.size(); iK2++) {
                        if (((org.jsoup.nodes.i) cG.get(iK2)).d.equals(iVar2.d)) {
                            iK++;
                        }
                    }
                    break;
                }
                break;
            default:
                org.jsoup.nodes.i iVar6 = (org.jsoup.nodes.i) iVar2.a;
                iK = 0;
                if (iVar6 != null) {
                    Iterator<E> it2 = iVar6.G().iterator();
                    while (it2.hasNext()) {
                        org.jsoup.nodes.i iVar7 = (org.jsoup.nodes.i) it2.next();
                        if (iVar7.d.equals(iVar2.d)) {
                            iK++;
                        }
                        if (iVar7 == iVar2) {
                            break;
                        }
                    }
                    break;
                }
                break;
        }
        int i = this.b;
        int i2 = this.a;
        if (i2 == 0) {
            return iK == i;
        }
        int i3 = iK - i;
        return i3 * i2 >= 0 && i3 % i2 == 0;
    }

    public final String b() {
        switch (this.c) {
            case 0:
                return "nth-child";
            case 1:
                return "nth-last-child";
            case 2:
                return "nth-last-of-type";
            default:
                return "nth-of-type";
        }
    }

    public String toString() {
        int i = this.b;
        int i2 = this.a;
        return i2 == 0 ? String.format(":%s(%d)", b(), Integer.valueOf(i)) : i == 0 ? String.format(":%s(%dn)", b(), Integer.valueOf(i2)) : String.format(":%s(%dn%+d)", b(), Integer.valueOf(i2), Integer.valueOf(i));
    }
}

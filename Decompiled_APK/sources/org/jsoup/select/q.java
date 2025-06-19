package org.jsoup.select;

/* loaded from: classes3.dex */
public final class q extends r {
    public final /* synthetic */ int b;

    public /* synthetic */ q(int i) {
        this.b = i;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        org.jsoup.nodes.i iVar3;
        org.jsoup.nodes.i iVarR;
        switch (this.b) {
            case 0:
                return (iVar == iVar2 || (iVar3 = (org.jsoup.nodes.i) iVar2.a) == null || !this.a.a(iVar, iVar3)) ? false : true;
            case 1:
                return (iVar == iVar2 || (iVarR = iVar2.R()) == null || !this.a.a(iVar, iVarR)) ? false : true;
            case 2:
                return !this.a.a(iVar, iVar2);
            case 3:
                if (iVar == iVar2) {
                    return false;
                }
                for (org.jsoup.nodes.i iVar4 = (org.jsoup.nodes.i) iVar2.a; iVar4 != null; iVar4 = (org.jsoup.nodes.i) iVar4.a) {
                    if (this.a.a(iVar, iVar4)) {
                        return true;
                    }
                    if (iVar4 == iVar) {
                        return false;
                    }
                }
                return false;
            default:
                if (iVar == iVar2) {
                    return false;
                }
                for (org.jsoup.nodes.i iVarR2 = iVar2.R(); iVarR2 != null; iVarR2 = iVarR2.R()) {
                    if (this.a.a(iVar, iVarR2)) {
                        return true;
                    }
                }
                return false;
        }
    }

    public final String toString() {
        switch (this.b) {
            case 0:
                return String.format("%s > ", this.a);
            case 1:
                return String.format("%s + ", this.a);
            case 2:
                return String.format(":not(%s)", this.a);
            case 3:
                return String.format("%s ", this.a);
            default:
                return String.format("%s ~ ", this.a);
        }
    }
}

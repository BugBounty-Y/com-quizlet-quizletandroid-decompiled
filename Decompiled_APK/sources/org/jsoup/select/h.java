package org.jsoup.select;

/* loaded from: classes3.dex */
public final class h extends m {
    public final int a;
    public final /* synthetic */ int b;

    public h(int i, int i2) {
        this.b = i2;
        this.a = i;
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        switch (this.b) {
            case 0:
                if (iVar2.K() == this.a) {
                }
                break;
            case 1:
                if (iVar2.K() > this.a) {
                }
                break;
            default:
                if (iVar == iVar2 || iVar2.K() >= this.a) {
                }
                break;
        }
        return false;
    }

    public final String toString() {
        switch (this.b) {
            case 0:
                return String.format(":eq(%d)", Integer.valueOf(this.a));
            case 1:
                return String.format(":gt(%d)", Integer.valueOf(this.a));
            default:
                return String.format(":lt(%d)", Integer.valueOf(this.a));
        }
    }
}

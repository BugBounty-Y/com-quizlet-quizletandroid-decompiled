package org.jsoup.select;

/* loaded from: classes3.dex */
public final class b extends c {
    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        for (int i = 0; i < this.b; i++) {
            if (((m) this.a.get(i)).a(iVar, iVar2)) {
                return true;
            }
        }
        return false;
    }

    public final String toString() {
        return org.jsoup.internal.a.f(this.a, ", ");
    }
}

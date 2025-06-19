package org.jsoup.select;

import java.util.Arrays;
import java.util.List;

/* loaded from: classes3.dex */
public final class a extends c {
    public a(List list) {
        this.a.addAll(list);
        this.b = this.a.size();
    }

    @Override // org.jsoup.select.m
    public final boolean a(org.jsoup.nodes.i iVar, org.jsoup.nodes.i iVar2) {
        for (int i = this.b - 1; i >= 0; i--) {
            if (!((m) this.a.get(i)).a(iVar, iVar2)) {
                return false;
            }
        }
        return true;
    }

    public final String toString() {
        return org.jsoup.internal.a.f(this.a, "");
    }

    public a(m... mVarArr) {
        this(Arrays.asList(mVarArr));
    }
}

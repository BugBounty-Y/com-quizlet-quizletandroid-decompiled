package org.jsoup.nodes;

import org.jsoup.parser.C;
import org.jsoup.parser.E;

/* loaded from: classes3.dex */
public final class l extends i {
    public final C j;

    public l(E e, b bVar) {
        super(e, null, bVar);
        this.j = new C(1);
    }

    @Override // org.jsoup.nodes.i
    /* renamed from: H */
    public final i clone() {
        return (l) super.clone();
    }

    @Override // org.jsoup.nodes.i, org.jsoup.nodes.n
    /* renamed from: clone */
    public final Object i() {
        return (l) super.clone();
    }

    @Override // org.jsoup.nodes.i, org.jsoup.nodes.n
    public final n i() {
        return (l) super.clone();
    }

    @Override // org.jsoup.nodes.n
    public final void z(n nVar) {
        super.z(nVar);
        this.j.remove(nVar);
    }
}

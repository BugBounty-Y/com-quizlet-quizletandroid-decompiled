package androidx.work.impl.constraints.controllers;

import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;

/* loaded from: classes.dex */
public final class a {
    public final /* synthetic */ c a;
    public final /* synthetic */ u b;

    public a(c cVar, u uVar) {
        this.a = cVar;
        this.b = uVar;
    }

    public final void a(Object obj) {
        c cVar = this.a;
        Object bVar = cVar.e(obj) ? new androidx.work.impl.constraints.b(cVar.d()) : androidx.work.impl.constraints.a.a;
        t tVar = (t) this.b;
        tVar.getClass();
        tVar.o(bVar);
    }
}

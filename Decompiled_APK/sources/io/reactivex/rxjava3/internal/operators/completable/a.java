package io.reactivex.rxjava3.internal.operators.completable;

import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.maybe.r;

/* loaded from: classes3.dex */
public final class a extends io.reactivex.rxjava3.core.a {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.a) this.b).b(new io.reactivex.rxjava3.internal.observers.e(2, bVar, (io.reactivex.rxjava3.core.d) this.c));
                break;
            case 1:
                ((io.reactivex.rxjava3.core.a) this.b).b(new e(bVar, (io.reactivex.rxjava3.functions.a) this.c, 0));
                break;
            case 2:
                j jVar = new j(bVar, (io.reactivex.rxjava3.functions.h) this.c);
                bVar.a(jVar);
                ((io.reactivex.rxjava3.core.a) this.b).b(jVar);
                break;
            case 3:
                l lVar = new l(bVar);
                bVar.a(lVar);
                ((c) this.c).b((k) lVar.c);
                ((h) this.b).b(lVar);
                break;
            case 4:
                io.reactivex.rxjava3.internal.observers.e eVar = new io.reactivex.rxjava3.internal.observers.e(3, bVar, (com.quizlet.login.authentication.login.a) this.c);
                bVar.a(eVar);
                ((r) this.b).e(eVar);
                break;
            default:
                io.reactivex.rxjava3.internal.observers.e eVar2 = new io.reactivex.rxjava3.internal.observers.e(8, bVar, (io.reactivex.rxjava3.functions.h) this.c);
                bVar.a(eVar2);
                ((p) this.b).j(eVar2);
                break;
        }
    }
}

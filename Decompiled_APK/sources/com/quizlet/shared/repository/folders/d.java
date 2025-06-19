package com.quizlet.shared.repository.folders;

import com.mayakapps.kache.u;
import com.quizlet.shared.cache.h;
import com.quizlet.shared.cache.i;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class d implements com.quizlet.shared.cache.a {
    public final /* synthetic */ int a = 1;
    public final kotlinx.coroutines.scheduling.e b;
    public final Object c;

    public d(u kache, kotlinx.coroutines.scheduling.e dispatcher) {
        Intrinsics.checkNotNullParameter(kache, "kache");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.c = kache;
        this.b = dispatcher;
    }

    @Override // com.quizlet.shared.cache.a
    public final Object a(kotlin.coroutines.jvm.internal.c cVar) {
        switch (this.a) {
            case 0:
                return E.J(this.b, new b(this, null), cVar);
            default:
                return E.J(this.b, new h(this, null), cVar);
        }
    }

    @Override // com.quizlet.shared.cache.a
    public final Object b(Object obj, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        switch (this.a) {
            case 0:
                Object objJ = E.J(this.b, new c(this, (com.quizlet.shared.models.api.folders.a) obj, null), cVar);
                if (objJ != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objJ2 = E.J(this.b, new i(this, obj, null), cVar);
                if (objJ2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }

    @Override // com.quizlet.shared.cache.a
    public final Object c(kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        switch (this.a) {
            case 0:
                Object objC = ((com.quizlet.shared.cache.a) this.c).c(cVar);
                if (objC != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objJ = E.J(this.b, new com.quizlet.shared.cache.g(this, null), cVar);
                if (objJ != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }

    public d(com.quizlet.shared.cache.a cache, kotlinx.coroutines.scheduling.e dispatcher) {
        Intrinsics.checkNotNullParameter(cache, "cache");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.c = cache;
        this.b = dispatcher;
    }
}

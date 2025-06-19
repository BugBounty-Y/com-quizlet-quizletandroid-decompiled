package com.quizlet.remote.model.progress;

import com.quizlet.data.model.C4127f1;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.service.G;
import com.quizlet.remote.service.s;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.completable.i;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.C5187l;
import retrofit2.InterfaceC5181f;
import retrofit2.L;
import retrofit2.u;

/* loaded from: classes3.dex */
public final class e implements h, q, io.reactivex.rxjava3.operators.d, InterfaceC5181f {
    public final Object a;
    public final Object b;

    public /* synthetic */ e(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c((AtomicReference) this.a, bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        Throwable thB = G.b((G) this.a, (L) ((com.quizlet.data.repository.folderset.c) this.b).b, it2);
        Objects.requireNonNull(thB, "throwable is null");
        return new io.reactivex.rxjava3.internal.operators.maybe.e(thB, 2);
    }

    @Override // retrofit2.InterfaceC5181f
    public Type b() {
        return (Type) this.a;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public void clear() {
        while (poll() != null && !isEmpty()) {
        }
    }

    public io.reactivex.rxjava3.core.a d(C4127f1 data) {
        Intrinsics.checkNotNullParameter(data, "progressReset");
        Intrinsics.checkNotNullParameter(data, "data");
        int iB = data.c.b();
        List model = A.b(new RemoteProgressReset(data.a, data.b, iB, data.d));
        com.quizlet.login.authentication.login.a aVar = (com.quizlet.login.authentication.login.a) this.a;
        Intrinsics.checkNotNullParameter(model, "model");
        g gVarG = ((s) aVar.b).b(new ApiPostBody<>(model)).g(c.a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.completable.c cVar = new io.reactivex.rxjava3.internal.operators.completable.c(gVarG, 6);
        d dVar = d.a;
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        i iVar = new i(cVar, gVar, dVar, bVar, bVar);
        Intrinsics.checkNotNullExpressionValue(iVar, "doOnError(...)");
        return iVar;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public boolean isEmpty() {
        return ((io.reactivex.rxjava3.internal.queue.a) ((AtomicReference) this.b).get()) == ((io.reactivex.rxjava3.internal.queue.a) ((AtomicReference) this.a).get());
    }

    @Override // retrofit2.InterfaceC5181f
    public Object j(u uVar) {
        Executor executor = (Executor) this.b;
        return executor == null ? uVar : new C5187l(executor, uVar);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public boolean offer(Object obj) {
        if (obj == null) {
            throw new NullPointerException("Null is not a valid element");
        }
        io.reactivex.rxjava3.internal.queue.a aVar = new io.reactivex.rxjava3.internal.queue.a();
        aVar.a = obj;
        ((io.reactivex.rxjava3.internal.queue.a) ((AtomicReference) this.a).getAndSet(aVar)).lazySet(aVar);
        return true;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((q) this.b).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((q) this.b).onSuccess(obj);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public Object poll() {
        io.reactivex.rxjava3.internal.queue.a aVar;
        AtomicReference atomicReference = (AtomicReference) this.b;
        io.reactivex.rxjava3.internal.queue.a aVar2 = (io.reactivex.rxjava3.internal.queue.a) atomicReference.get();
        io.reactivex.rxjava3.internal.queue.a aVar3 = (io.reactivex.rxjava3.internal.queue.a) aVar2.get();
        if (aVar3 != null) {
            Object obj = aVar3.a;
            aVar3.a = null;
            atomicReference.lazySet(aVar3);
            aVar2.lazySet(null);
            return obj;
        }
        if (aVar2 == ((io.reactivex.rxjava3.internal.queue.a) ((AtomicReference) this.a).get())) {
            return null;
        }
        do {
            aVar = (io.reactivex.rxjava3.internal.queue.a) aVar2.get();
        } while (aVar == null);
        Object obj2 = aVar.a;
        aVar.a = null;
        atomicReference.lazySet(aVar);
        aVar2.lazySet(null);
        return obj2;
    }

    public e(com.quizlet.login.authentication.login.a dataStore, a mapper) {
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.a = dataStore;
        this.b = mapper;
    }

    public e() {
        AtomicReference atomicReference = new AtomicReference();
        this.a = atomicReference;
        AtomicReference atomicReference2 = new AtomicReference();
        this.b = atomicReference2;
        io.reactivex.rxjava3.internal.queue.a aVar = new io.reactivex.rxjava3.internal.queue.a();
        atomicReference2.lazySet(aVar);
    }
}

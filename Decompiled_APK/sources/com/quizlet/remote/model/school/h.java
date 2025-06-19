package com.quizlet.remote.model.school;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.remote.service.G;
import com.quizlet.remote.service.x;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.internal.operators.completable.m;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.C;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.reflect.o;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5043a0;
import kotlinx.serialization.internal.C5063q;
import kotlinx.serialization.internal.InterfaceC5045b0;
import kotlinx.serialization.internal.U;
import kotlinx.serialization.internal.r;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import retrofit2.InterfaceC5182g;
import retrofit2.L;
import retrofit2.S;
import retrofit2.u;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.core.b, InterfaceC5045b0, InterfaceC5077f {
    public final Object a;
    public final Object b;

    public h(G g, com.quizlet.data.repository.folderset.c cVar) {
        this.a = g;
        this.b = cVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((q) this.a).a(bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        Throwable thB = G.b((G) this.a, (L) ((com.quizlet.data.repository.folderset.c) this.b).b, it2);
        int i = io.reactivex.rxjava3.core.e.a;
        Objects.requireNonNull(thB, "throwable is null");
        return new io.reactivex.rxjava3.internal.operators.flowable.c(new io.reactivex.rxjava3.internal.functions.c(thB), 0);
    }

    @Override // kotlinx.serialization.internal.InterfaceC5045b0
    public Object b(kotlin.reflect.c key, ArrayList types) {
        Object objB;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(types, "types");
        Object obj = ((r) this.b).get(kotlin.jvm.a.b(key));
        Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
        U u = (U) obj;
        Object objA = u.reference.get();
        if (objA == null) {
            objA = u.a(new C5063q());
        }
        C5043a0 c5043a0 = (C5043a0) objA;
        ArrayList arrayList = new ArrayList(C.q(types, 10));
        Iterator it2 = types.iterator();
        while (it2.hasNext()) {
            arrayList.add(new kotlinx.serialization.internal.L((o) it2.next()));
        }
        ConcurrentHashMap concurrentHashMap = c5043a0.a;
        Object obj2 = concurrentHashMap.get(arrayList);
        if (obj2 == null) {
            try {
                p pVar = kotlin.r.b;
                objB = (KSerializer) ((Function2) this.a).invoke(key, types);
            } catch (Throwable th) {
                p pVar2 = kotlin.r.b;
                objB = Z.b(th);
            }
            kotlin.r rVar = new kotlin.r(objB);
            Object objPutIfAbsent = concurrentHashMap.putIfAbsent(arrayList, rVar);
            obj2 = objPutIfAbsent == null ? rVar : objPutIfAbsent;
        }
        Intrinsics.checkNotNullExpressionValue(obj2, "getOrPut(...)");
        return ((kotlin.r) obj2).a;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        Object obj;
        m mVar = (m) this.b;
        com.quizlet.data.repository.folderwithcreator.b bVar = (com.quizlet.data.repository.folderwithcreator.b) mVar.d;
        q qVar = (q) this.a;
        if (bVar != null) {
            try {
                obj = Boolean.TRUE;
            } catch (Throwable th) {
                x7.b(th);
                qVar.onError(th);
                return;
            }
        } else {
            obj = mVar.b;
        }
        if (obj == null) {
            qVar.onError(new NullPointerException("The value supplied is null"));
        } else {
            qVar.onSuccess(obj);
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        ((q) this.a).onError(th);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e interfaceC5076e, IOException iOException) {
        try {
            ((InterfaceC5182g) this.a).f((u) this.b, iOException);
        } catch (Throwable th) {
            S.t(th);
            th.printStackTrace();
        }
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e interfaceC5076e, H h) {
        InterfaceC5182g interfaceC5182g = (InterfaceC5182g) this.a;
        u uVar = (u) this.b;
        try {
            try {
                interfaceC5182g.k(uVar, uVar.d(h));
            } catch (Throwable th) {
                S.t(th);
                th.printStackTrace();
            }
        } catch (Throwable th2) {
            S.t(th2);
            try {
                interfaceC5182g.f(uVar, th2);
            } catch (Throwable th3) {
                S.t(th3);
                th3.printStackTrace();
            }
        }
    }

    public /* synthetic */ h(Object obj, Object obj2) {
        this.b = obj;
        this.a = obj2;
    }

    public h(x service, com.quizlet.remote.model.school.memberships.a remoteSchoolMembershipMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(remoteSchoolMembershipMapper, "remoteSchoolMembershipMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }

    public h(Function2 compute) {
        Intrinsics.checkNotNullParameter(compute, "compute");
        this.a = compute;
        this.b = new r();
    }
}

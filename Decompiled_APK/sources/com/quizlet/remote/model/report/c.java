package com.quizlet.remote.model.report;

import com.facebook.login.E;
import com.quizlet.features.folders.composables.W;
import com.quizlet.remote.service.G;
import com.quizlet.remote.service.w;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.observers.e;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5057k;
import kotlinx.serialization.internal.U;
import kotlinx.serialization.internal.m0;
import kotlinx.serialization.internal.r;
import retrofit2.C5187l;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class c implements h, io.reactivex.rxjava3.core.b, m0, InterfaceC5182g {
    public final Object a;
    public final Object b;

    public /* synthetic */ c(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c((e) this.a, bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return p.d(G.b((G) this.a, (L) ((com.quizlet.data.repository.folderset.c) this.b).b, it2));
    }

    @Override // kotlinx.serialization.internal.m0
    public KSerializer b(kotlin.reflect.c key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = ((r) this.b).get(kotlin.jvm.a.b(key));
        Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
        U u = (U) obj;
        Object objA = u.reference.get();
        if (objA == null) {
            objA = u.a(new W(16, this, key));
        }
        return ((C5057k) objA).a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(int r11, int r12, java.lang.String r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.remote.model.report.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.remote.model.report.a r0 = (com.quizlet.remote.model.report.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.report.a r0 = new com.quizlet.remote.model.report.a
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L30
            if (r2 != r3) goto L28
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r5 = r10
            goto L4a
        L28:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.remote.model.report.b r4 = new com.quizlet.remote.model.report.b
            r9 = 0
            r5 = r10
            r6 = r11
            r7 = r12
            r8 = r13
            r4.<init>(r5, r6, r7, r8, r9)
            r0.l = r3
            java.lang.Object r11 = r5.b
            kotlinx.coroutines.y r11 = (kotlinx.coroutines.AbstractC5040y) r11
            java.lang.Object r14 = kotlinx.coroutines.E.J(r11, r4, r0)
            if (r14 != r1) goto L4a
            return r1
        L4a:
            kotlin.r r14 = (kotlin.r) r14
            java.lang.Object r11 = r14.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.report.c.c(int, int, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        ((C5187l) this.b).a.execute(new E(this, (InterfaceC5182g) this.a, th, 15));
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, K k) {
        ((C5187l) this.b).a.execute(new E(this, (InterfaceC5182g) this.a, k, 14));
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        ((io.reactivex.rxjava3.core.b) this.b).onComplete();
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        ((io.reactivex.rxjava3.core.b) this.b).onError(th);
    }

    public c(w service, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }

    public c(Function1 compute) {
        Intrinsics.checkNotNullParameter(compute, "compute");
        this.a = compute;
        this.b = new r();
    }

    public c(C5187l c5187l, InterfaceC5182g interfaceC5182g) {
        this.b = c5187l;
        this.a = interfaceC5182g;
    }
}

package com.quizlet.quizletandroid.ui.common.ads;

import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C4634a j;
    public d0 k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ E n;
    public final /* synthetic */ J o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(E e, J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = e;
        this.o = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        A a = new A(this.n, this.o, hVar);
        a.m = obj;
        return a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlin.v) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        C4639f c4639f;
        C4634a c4634a;
        d0 d0Var;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        if (i == 0) {
            Z.e(obj);
            kotlin.v vVar = (kotlin.v) this.m;
            c4639f = (C4639f) vVar.a;
            c4634a = (C4634a) vVar.b;
            d0 d0VarB = e0.b(1, 1, null, 4);
            Unit unit = Unit.a;
            this.m = c4639f;
            this.j = c4634a;
            this.k = d0VarB;
            this.l = 1;
            if (d0VarB.emit(unit, this) == aVar) {
                return aVar;
            }
            d0Var = d0VarB;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            d0Var = this.k;
            c4634a = this.j;
            c4639f = (C4639f) this.m;
            Z.e(obj);
        }
        W w = c4639f.b;
        com.quizlet.ads.c cVar = c4634a.a;
        E e = this.n;
        com.quizlet.analytics.marketing.appsflyer.d flow1 = new com.quizlet.analytics.marketing.appsflyer.d(w, 5);
        C1087t flow2 = new C1087t(new t(d0Var, null, e, cVar));
        int i2 = com.quizlet.qutils.coroutines.c.a;
        Intrinsics.checkNotNullParameter(flow1, "flow1");
        Intrinsics.checkNotNullParameter(flow2, "flow2");
        z zVar = new z(new J0(new C1087t(new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(flow2, flow1, new com.quizlet.qutils.coroutines.a(3, 1, null), 3), 5), new x(this.o, null), 5), c4634a, c4639f, d0Var);
        c4639f.c.c();
        return zVar;
    }
}

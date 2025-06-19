package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.setpage.viewmodel.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4438l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public X j;
    public int k;
    public final /* synthetic */ P l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C4438l(P p, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = p;
        this.m = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4438l(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4438l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        X x;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        P p = this.l;
        if (i == 0) {
            Z.e(obj);
            p.d1.j(com.quizlet.features.setpage.screenstates.q.a);
            X x2 = p.i1;
            this.j = x2;
            this.k = 1;
            Object objInvoke = this.m.invoke(this);
            if (objInvoke == aVar) {
                return aVar;
            }
            x = x2;
            obj = objInvoke;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            x = this.j;
            Z.e(obj);
        }
        x.j(obj);
        p.d1.j(com.quizlet.features.setpage.screenstates.p.a);
        return Unit.a;
    }
}

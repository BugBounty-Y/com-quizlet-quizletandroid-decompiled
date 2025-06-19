package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ N m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(N n, kotlin.coroutines.h hVar, boolean z) {
        super(2, hVar);
        this.l = z;
        this.m = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        p pVar = new p(this.m, hVar, this.l);
        pVar.k = obj;
        return pVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.C c;
        kotlinx.coroutines.C c2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            c = (kotlinx.coroutines.C) this.k;
            if (this.l) {
                this.k = c;
                this.j = 1;
                if (kotlinx.coroutines.E.n(200L, this) == aVar) {
                    return aVar;
                }
                c2 = c;
            }
            N n = this.m;
            kotlinx.coroutines.E.A(c, null, null, new C4333n(n, null), 3);
            kotlinx.coroutines.E.A(c, null, null, new C4334o(n, null), 3);
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        c2 = (kotlinx.coroutines.C) this.k;
        Z.e(obj);
        c = c2;
        N n2 = this.m;
        kotlinx.coroutines.E.A(c, null, null, new C4333n(n2, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new C4334o(n2, null), 3);
        return Unit.a;
    }
}

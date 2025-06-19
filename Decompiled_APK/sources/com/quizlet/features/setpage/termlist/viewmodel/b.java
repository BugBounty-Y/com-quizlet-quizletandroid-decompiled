package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.setpage.termlist.data.n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ j k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(j jVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.k, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((n) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        n nVar = (n) this.j;
        j jVar = this.k;
        do {
            s0Var = jVar.h;
            value = s0Var.getValue();
        } while (!s0Var.k(value, nVar));
        return Unit.a;
    }
}

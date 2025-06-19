package com.quizlet.features.home.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.v2;
import com.quizlet.features.home.data.t;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.classmembership.c cVar2 = cVar.b;
            this.j = 1;
            obj = cVar2.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        v2 v2Var = (v2) obj;
        s0 s0Var = cVar.f;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new t(v2Var)));
        return Unit.a;
    }
}

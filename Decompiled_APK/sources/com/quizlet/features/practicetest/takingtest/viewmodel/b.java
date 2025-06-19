package com.quizlet.features.practicetest.takingtest.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.features.practicetest.takingtest.data.G;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        l lVar = this.k;
        if (i == 0) {
            Z.e(obj);
            androidx.work.impl.model.e eVar = lVar.d;
            this.j = 1;
            obj = eVar.l(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        if (!lVar.f.b() || zBooleanValue) {
            E.A(p0.j(lVar), lVar.h, null, new i(lVar, null), 2);
        } else {
            do {
                s0Var = lVar.k;
                value = s0Var.getValue();
            } while (!s0Var.k(value, new G(com.quizlet.features.practicetest.common.data.g.a)));
        }
        return Unit.a;
    }
}

package com.quizlet.login.intro.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.intro.data.u;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, h hVar) {
        super(2, hVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar2 = eVar.f;
            eVar2.getClass();
            obj = E.J((AbstractC5040y) eVar2.e, new com.quizlet.features.infra.compatibility.d(eVar2, false, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.infra.compatibility.a aVar2 = (com.quizlet.features.infra.compatibility.a) obj;
        if (aVar2 != null) {
            Function0 function0 = aVar2.c;
            s0 s0Var = eVar.m;
            if (function0 == null) {
                com.quizlet.features.infra.compatibility.a aVarA = com.quizlet.features.infra.compatibility.a.a(aVar2, new com.quizlet.featuregate.growthbook.a(eVar, 28));
                do {
                    value2 = s0Var.getValue();
                } while (!s0Var.k(value2, u.a((u) value2, aVarA, null, false, 27)));
            } else {
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, u.a((u) value, aVar2, null, false, 27)));
            }
        }
        return Unit.a;
    }
}

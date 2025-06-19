package com.quizlet.assembly.compose.modals;

import androidx.compose.material3.F3;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ x k;
    public final /* synthetic */ F3 l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(x xVar, F3 f3, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = f3;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        x xVar = this.k;
        if (i == 0) {
            Z.e(obj);
            if (((L0) xVar.a).getValue() == y.c) {
                this.j = 1;
                if (this.l.b(this) == aVar) {
                    return aVar;
                }
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        ((Function0) this.m.getValue()).invoke();
        xVar.c();
        return Unit.a;
    }
}

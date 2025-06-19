package com.quizlet.ui.compose;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.compose.runtime.C0776c;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4393l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes3.dex */
public final class Q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ C0466e l;
    public final /* synthetic */ Function1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(long j, C0466e c0466e, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = c0466e;
        this.m = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Q(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            InterfaceC4992i interfaceC4992iM = kotlinx.coroutines.flow.e0.m(kotlinx.coroutines.flow.e0.l(C0776c.F(new C4393l(this.l, 4)), this.k));
            C0496b c0496b = new C0496b(this.m, 20);
            this.j = 1;
            if (interfaceC4992iM.b(c0496b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}

package com.quizlet.features.flashcards.views.composables;

import androidx.compose.foundation.gestures.k1;
import androidx.compose.ui.input.pointer.B;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.U;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ x l;
    public final /* synthetic */ Function0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(x xVar, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = xVar;
        this.m = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.l, this.m, hVar);
        dVar.k = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            B b = (B) this.k;
            U u = new U(this.l, 28);
            com.quizlet.assembly.compose.input.d dVar = new com.quizlet.assembly.compose.input.d(7, this.m);
            this.j = 1;
            if (k1.d(b, u, dVar, this, 5) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

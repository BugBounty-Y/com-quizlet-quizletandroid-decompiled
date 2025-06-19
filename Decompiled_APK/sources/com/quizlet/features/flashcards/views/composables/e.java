package com.quizlet.features.flashcards.views.composables;

import androidx.compose.foundation.gestures.k1;
import androidx.compose.ui.input.pointer.B;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.u0;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ StudiableText m;
    public final /* synthetic */ Function0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function1 function1, StudiableText studiableText, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = function1;
        this.m = studiableText;
        this.n = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.l, this.m, this.n, hVar);
        eVar.k = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            B b = (B) this.k;
            u0 u0Var = new u0(21, (Object) this.m, this.l);
            com.quizlet.assembly.compose.input.d dVar = new com.quizlet.assembly.compose.input.d(8, this.n);
            this.j = 1;
            if (k1.d(b, u0Var, dVar, this, 5) == aVar) {
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

package com.quizlet.features.emailconfirmation.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4135i0;
import com.quizlet.features.emailconfirmation.ui.composables.s;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.k, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C4135i0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        com.quizlet.features.emailconfirmation.data.states.a aVar;
        String str;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C4135i0 c4135i0 = (C4135i0) this.j;
        boolean z = c4135i0.u;
        f fVar = this.k;
        if (z) {
            fVar.i.h(Unit.a);
            do {
                s0Var = fVar.f;
                value = s0Var.getValue();
                aVar = (com.quizlet.features.emailconfirmation.data.states.a) value;
                str = c4135i0.q;
                if (str == null) {
                    str = "";
                }
            } while (!s0Var.k(value, com.quizlet.features.emailconfirmation.data.states.a.a(aVar, str, c4135i0.w ? s.b : s.a, 4)));
        } else {
            fVar.g.h(com.quizlet.features.emailconfirmation.data.events.a.b);
        }
        return Unit.a;
    }
}

package com.quizlet.quizletandroid.ui.library;

import com.google.android.gms.internal.mlkit_vision_camera.I1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c0 c0Var = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            io.reactivex.rxjava3.internal.operators.single.g gVarU = c0Var.g.u();
            this.j = 1;
            obj = I1.b(gVarU, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        s0 s0Var = c0Var.t;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value, null, null, null, null, null, !zBooleanValue, false, false, 223)));
        return Unit.a;
    }
}

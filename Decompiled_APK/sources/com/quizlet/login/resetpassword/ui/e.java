package com.quizlet.login.resetpassword.ui;

import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.resetpassword.data.f;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Q0 k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ Function0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Q0 q0, Function1 function1, Function0 function0, h hVar) {
        super(2, hVar);
        this.k = q0;
        this.l = function1;
        this.m = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        e eVar = new e(this.k, this.l, this.m, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((f) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        f fVar = (f) this.j;
        if (fVar instanceof com.quizlet.login.resetpassword.data.e) {
            Q0 q0 = this.k;
            if (q0 != null) {
                ((C0957n0) q0).a();
            }
            this.l.invoke(((com.quizlet.login.resetpassword.data.e) fVar).a);
        } else {
            if (!Intrinsics.b(fVar, com.quizlet.login.resetpassword.data.d.a)) {
                throw new NoWhenBranchMatchedException();
            }
            this.m.invoke();
        }
        return Unit.a;
    }
}

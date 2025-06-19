package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.composable.n;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
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
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.quizletandroid.ui.setcreation.managers.b bVar = eVar.f;
            this.j = 1;
            obj = bVar.a(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (!((Boolean) obj).booleanValue()) {
            X x = eVar.l;
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.under_set_creation_dialog_title, C4933y.P(args));
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            com.quizlet.qutils.string.f fVar2 = new com.quizlet.qutils.string.f(R.string.under_set_creation_dialog_positive_button, C4933y.P(args2));
            Object[] args3 = new Object[0];
            Intrinsics.checkNotNullParameter(args3, "args");
            x.j(new com.quizlet.quizletandroid.ui.setcreation.navigation.d(fVar, fVar2, new com.quizlet.qutils.string.f(R.string.close, C4933y.P(args3)), new n(0, this.k, e.class, "onClickResendEmail", "onClickResendEmail()V", 0, 13), new n(0, this.k, e.class, "onClickClose", "onClickClose()V", 0, 14)));
        }
        return Unit.a;
    }
}

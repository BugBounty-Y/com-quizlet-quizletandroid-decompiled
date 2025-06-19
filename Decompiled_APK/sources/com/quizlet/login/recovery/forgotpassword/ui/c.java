package com.quizlet.login.recovery.forgotpassword.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ ForgotPasswordDialogFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(ForgotPasswordDialogFragment forgotPasswordDialogFragment, h hVar) {
        super(2, hVar);
        this.k = forgotPasswordDialogFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = ForgotPasswordDialogFragment.C;
            ForgotPasswordDialogFragment forgotPasswordDialogFragment = this.k;
            d0 d0Var = ((com.quizlet.login.recovery.forgotpassword.viewmodel.e) forgotPasswordDialogFragment.B.getValue()).f;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, forgotPasswordDialogFragment, ForgotPasswordDialogFragment.class, "handleForgotPasswordEvent", "handleForgotPasswordEvent(Lcom/quizlet/login/recovery/forgotpassword/data/ForgotPasswordEvent;)V", 4, 11);
            this.j = 1;
            if (e0.i(d0Var, cVar, this) == aVar) {
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

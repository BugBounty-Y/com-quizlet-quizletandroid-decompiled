package com.quizlet.quizletandroid.ui.login;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.quizletandroid.ui.login.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4683c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ BaseSignupFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4683c(BaseSignupFragment baseSignupFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = baseSignupFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4683c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4683c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            BaseSignupFragment baseSignupFragment = this.k;
            d0 d0Var = ((com.quizlet.quizletandroid.ui.login.viewmodels.j) baseSignupFragment.n.getValue()).b;
            C4682b c4682b = new C4682b(baseSignupFragment, null);
            this.j = 1;
            if (e0.i(d0Var, c4682b, this) == aVar) {
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

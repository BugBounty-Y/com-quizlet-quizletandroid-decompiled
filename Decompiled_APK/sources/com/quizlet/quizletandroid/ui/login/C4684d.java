package com.quizlet.quizletandroid.ui.login;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.login.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4684d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ BaseSignupFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4684d(BaseSignupFragment baseSignupFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = baseSignupFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4684d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4684d) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            BaseSignupFragment baseSignupFragment = this.k;
            J viewLifecycleOwner = baseSignupFragment.getViewLifecycleOwner();
            Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            C4683c c4683c = new C4683c(baseSignupFragment, null);
            this.j = 1;
            if (p0.m(viewLifecycleOwner, b, c4683c, this) == aVar) {
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

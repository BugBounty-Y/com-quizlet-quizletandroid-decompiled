package com.quizlet.security.challenge.activity;

import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ SecurityChallengeActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(SecurityChallengeActivity securityChallengeActivity, h hVar) {
        super(2, hVar);
        this.k = securityChallengeActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            throw new KotlinNothingValueException();
        }
        Z.e(obj);
        SecurityChallengeActivity securityChallengeActivity = this.k;
        d0 d0Var = ((com.quizlet.security.challenge.viewmodel.d) securityChallengeActivity.g.getValue()).h;
        C0496b c0496b = new C0496b(securityChallengeActivity, 18);
        this.j = 1;
        d0Var.getClass();
        d0.m(d0Var, c0496b, this);
        return aVar;
    }
}

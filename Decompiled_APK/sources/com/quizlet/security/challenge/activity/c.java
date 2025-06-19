package com.quizlet.security.challenge.activity;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.B;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ SecurityChallengeActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(SecurityChallengeActivity securityChallengeActivity, h hVar) {
        super(2, hVar);
        this.k = securityChallengeActivity;
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
            B b = B.c;
            SecurityChallengeActivity securityChallengeActivity = this.k;
            b bVar = new b(securityChallengeActivity, null);
            this.j = 1;
            if (p0.m(securityChallengeActivity, b, bVar, this) == aVar) {
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

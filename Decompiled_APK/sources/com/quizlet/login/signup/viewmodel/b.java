package com.quizlet.login.signup.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.common.interactors.data.v;
import com.quizlet.login.signup.data.PromptParentEmailData;
import com.quizlet.login.signup.data.n;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ v j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(v vVar, g gVar, h hVar) {
        super(2, hVar);
        this.j = vVar;
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        v vVar = this.j;
        vVar.getClass();
        this.k.h.h(new n(new PromptParentEmailData(vVar.a, "email", com.quizlet.login.oldlogin.b.b)));
        return Unit.a;
    }
}

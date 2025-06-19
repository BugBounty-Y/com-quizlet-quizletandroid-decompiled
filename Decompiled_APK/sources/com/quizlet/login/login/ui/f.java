package com.quizlet.login.login.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.login.data.j;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.infra.google.e k;
    public final /* synthetic */ com.quizlet.login.login.viewmodel.a l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.features.infra.google.e eVar, com.quizlet.login.login.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objC;
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            objC = this.k.c(this);
            if (objC == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objC = ((r) obj).a;
        }
        p pVar = r.b;
        boolean z = objC instanceof q;
        com.quizlet.login.login.viewmodel.a aVar2 = this.l;
        if (!z && (str = (String) objC) != null) {
            ((com.quizlet.login.login.viewmodel.f) aVar2).E(new com.quizlet.login.login.data.i(str));
        }
        Throwable thA = r.a(objC);
        if (thA != null) {
            ((com.quizlet.login.login.viewmodel.f) aVar2).E(new j(thA));
        }
        return Unit.a;
    }
}

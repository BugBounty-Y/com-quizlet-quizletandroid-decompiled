package com.quizlet.login.intro.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.infra.google.e k;
    public final /* synthetic */ com.quizlet.login.intro.viewmodel.a l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.features.infra.google.e eVar, com.quizlet.login.intro.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            objB = this.k.b(this);
            if (objB == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objB = ((r) obj).a;
        }
        p pVar = r.b;
        boolean z = objB instanceof q;
        com.quizlet.login.intro.viewmodel.a aVar2 = this.l;
        if (!z && (str = (String) objB) != null) {
            ((com.quizlet.login.intro.viewmodel.e) aVar2).C(new com.quizlet.login.intro.data.g(str));
        }
        Throwable thA = r.a(objB);
        if (thA != null) {
            ((com.quizlet.login.intro.viewmodel.e) aVar2).C(new com.quizlet.login.intro.data.h(thA));
        }
        return Unit.a;
    }
}

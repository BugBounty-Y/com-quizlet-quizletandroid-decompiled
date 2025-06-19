package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.setpage.viewmodel.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4442p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4442p(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4442p(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4442p) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            P p = this.k;
            com.quizlet.features.setpage.studymodes.viewmodel.a aVar = p.F;
            long jD = p.D();
            this.j = 1;
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s sVar = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s) aVar;
            sVar.getClass();
            Object objJ = kotlinx.coroutines.E.J(sVar.i, new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.q(sVar, jD, null), this);
            if (objJ != obj2) {
                objJ = Unit.a;
            }
            if (objJ == obj2) {
                return obj2;
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

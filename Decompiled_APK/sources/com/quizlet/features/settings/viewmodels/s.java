package com.quizlet.features.settings.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ u k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(u uVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = uVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objQ;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        u uVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            objQ = uVar.d.q(this.l, this);
            if (objQ == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objQ = ((kotlin.r) obj).a;
        }
        kotlin.p pVar = kotlin.r.b;
        if (!(objQ instanceof kotlin.q)) {
            u.B(uVar, (String) objQ);
        }
        Throwable thA = kotlin.r.a(objQ);
        if (thA != null) {
            uVar.A(new com.quizlet.features.settings.composables.x(1, uVar, u.class, "handleReAuthenticateSSOError", "handleReAuthenticateSSOError(Lcom/quizlet/api/model/ServerProvidedError;)V", 0, 11), thA);
        }
        return Unit.a;
    }
}

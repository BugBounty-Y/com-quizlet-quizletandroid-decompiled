package com.quizlet.features.userprofile.data;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ x k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            x xVar = this.k;
            com.quizlet.features.userprofile.a aVar2 = xVar.f;
            aVar2.getClass();
            aVar2.a.l(com.quizlet.features.userprofile.a.a("clicked_upgrade"));
            if (xVar.d.r != null) {
                d0 d0Var = xVar.l;
                com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.r;
                Intrinsics.checkNotNullParameter("chiclet", "upgradeSource");
                Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
                g gVar = new g();
                this.j = 1;
                if (d0Var.emit(gVar, this) == aVar) {
                    return aVar;
                }
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

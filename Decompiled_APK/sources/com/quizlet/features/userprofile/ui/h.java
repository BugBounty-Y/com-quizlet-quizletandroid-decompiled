package com.quizlet.features.userprofile.ui;

import androidx.activity.compose.o;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.userprofile.navigation.b k;
    public final /* synthetic */ o l;
    public final /* synthetic */ o m;
    public final /* synthetic */ Function0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(com.quizlet.features.userprofile.navigation.b bVar, o oVar, o oVar2, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = oVar;
        this.m = oVar2;
        this.n = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.k, this.l, this.m, this.n, hVar);
        hVar2.j = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((com.quizlet.features.userprofile.data.h) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.userprofile.data.h hVar = (com.quizlet.features.userprofile.data.h) this.j;
        boolean zB = Intrinsics.b(hVar, com.quizlet.features.userprofile.data.c.a);
        com.quizlet.features.userprofile.navigation.b bVar = this.k;
        if (zB) {
            bVar.e();
        } else if (hVar instanceof com.quizlet.features.userprofile.data.e) {
            com.quizlet.features.userprofile.data.e eVar = (com.quizlet.features.userprofile.data.e) hVar;
            bVar.a(eVar.a, eVar.b, this.l);
        } else if (Intrinsics.b(hVar, com.quizlet.features.userprofile.data.f.a)) {
            bVar.b();
        } else if (hVar instanceof com.quizlet.features.userprofile.data.g) {
            ((com.quizlet.features.userprofile.data.g) hVar).getClass();
            bVar.i("chiclet", com.quizlet.features.infra.models.upgrade.a.r, this.m);
        } else if (Intrinsics.b(hVar, com.quizlet.features.userprofile.data.d.a)) {
            bVar.c();
        } else {
            if (!Intrinsics.b(hVar, com.quizlet.features.userprofile.data.b.a)) {
                throw new NoWhenBranchMatchedException();
            }
            this.n.invoke();
        }
        return Unit.a;
    }
}

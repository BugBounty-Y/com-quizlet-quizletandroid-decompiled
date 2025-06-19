package com.quizlet.features.infra.folder.create.composables;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ x k;
    public final /* synthetic */ x l;
    public final /* synthetic */ x m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(x xVar, x xVar2, x xVar3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = xVar2;
        this.m = xVar3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.k, this.l, this.m, hVar);
        nVar.j = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((com.quizlet.features.infra.folder.create.coursefolder.data.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.infra.folder.create.coursefolder.data.c cVar = (com.quizlet.features.infra.folder.create.coursefolder.data.c) this.j;
        this.k.c();
        if (Intrinsics.b(cVar, com.quizlet.features.infra.folder.create.coursefolder.data.a.a)) {
            x.d(this.l);
        } else {
            if (!Intrinsics.b(cVar, com.quizlet.features.infra.folder.create.coursefolder.data.b.a)) {
                throw new NoWhenBranchMatchedException();
            }
            x.d(this.m);
        }
        return Unit.a;
    }
}

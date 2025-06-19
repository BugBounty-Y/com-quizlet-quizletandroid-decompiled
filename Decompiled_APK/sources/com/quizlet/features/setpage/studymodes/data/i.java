package com.quizlet.features.setpage.studymodes.data;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.remote.model.notes.e l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(com.quizlet.remote.model.notes.e eVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = eVar;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.l, this.m, hVar);
        iVar.k = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C c = (C) this.k;
            com.quizlet.remote.model.notes.e eVar = this.l;
            long j = this.m;
            List listJ = B.j(E.A(c, null, null, new f(eVar, j, null), 3), E.A(c, null, null, new g(eVar, j, null), 3), E.A(c, null, null, new h(eVar, j, null), 3));
            this.j = 1;
            if (E.y(listJ, this) == aVar) {
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

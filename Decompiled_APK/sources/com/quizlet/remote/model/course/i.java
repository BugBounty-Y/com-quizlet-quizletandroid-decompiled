package com.quizlet.remote.model.course;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ n k;
    public final /* synthetic */ String l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(n nVar, String str, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
        this.l = str;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        n nVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.remote.service.i iVar = (com.quizlet.remote.service.i) nVar.a;
            this.j = 1;
            obj = iVar.d(this.l, this.m, 1, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return n.a(nVar, (K) obj);
    }
}

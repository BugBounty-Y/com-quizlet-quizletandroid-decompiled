package com.quizlet.features.userprofile.data;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ x k;
    public final /* synthetic */ com.quizlet.qutils.string.g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(x xVar, com.quizlet.qutils.string.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            Object objEmit = this.k.m.emit(new com.quizlet.features.infra.snackbar.m(this.l), this);
            if (objEmit != aVar) {
                objEmit = Unit.a;
            }
            if (objEmit == aVar) {
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

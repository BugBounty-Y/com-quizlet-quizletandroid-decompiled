package com.quizlet.features.practicetest.detail.usecase;

import androidx.camera.camera2.internal.c0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c0 c0Var, String str, h hVar) {
        super(2, hVar);
        this.k = c0Var;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        com.quizlet.data.repository.activitycenter.b bVar = (com.quizlet.data.repository.activitycenter.b) this.k.c;
        this.j = 1;
        Object objK = bVar.k(this.l, this);
        return objK == aVar ? aVar : objK;
    }
}

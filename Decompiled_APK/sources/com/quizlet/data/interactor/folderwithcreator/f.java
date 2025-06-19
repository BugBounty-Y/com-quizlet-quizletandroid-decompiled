package com.quizlet.data.interactor.folderwithcreator;

import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ m j;
    public final /* synthetic */ long k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(m mVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = mVar;
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        m mVar = this.j;
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) mVar.d;
        return e0.s(new J0(new C1087t(new d(e0.m(e0.s(K1.f(((com.quizlet.data.repository.folderwithcreator.e) cVar.c).f(this.k)), (AbstractC5040y) cVar.b)), null)), new b(3, 0, null)), (AbstractC5040y) mVar.c);
    }
}

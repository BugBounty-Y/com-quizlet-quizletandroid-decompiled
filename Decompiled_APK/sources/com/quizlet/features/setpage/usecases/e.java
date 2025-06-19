package com.quizlet.features.setpage.usecases;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.runtime.internal.j k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(androidx.compose.runtime.internal.j jVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
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
        io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) this.k.d;
        io.reactivex.rxjava3.internal.operators.single.j jVar = io.reactivex.rxjava3.internal.operators.single.j.a;
        Intrinsics.checkNotNullExpressionValue(jVar, "never(...)");
        J0 j0 = new J0(K1.f(dVar.o(this.l, jVar)), new com.quizlet.data.interactor.folderwithcreator.b(3, 2, null));
        this.j = 1;
        Object objV = e0.v(j0, this);
        return objV == aVar ? aVar : objV;
    }
}

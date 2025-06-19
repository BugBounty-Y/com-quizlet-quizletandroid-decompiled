package com.quizlet.upgrade.data;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.upgrade.data.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4840h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ io.reactivex.rxjava3.internal.operators.maybe.h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4840h(io.reactivex.rxjava3.internal.operators.maybe.h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4840h(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4840h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        this.j = 1;
        Object objD = I1.d(this.k, this);
        return objD == aVar ? aVar : objD;
    }
}

package com.quizlet.remote.model.user.emailconfirmation;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.user.FullUserDataResponse;
import com.quizlet.remote.service.E;
import io.reactivex.rxjava3.core.p;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class b extends i implements Function1 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(1, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((b) create((h) obj)).invokeSuspend(Unit.a);
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
        p<ApiThreeWrapper<FullUserDataResponse>> pVarF = ((E) this.k.a).f();
        this.j = 1;
        Object objB = I1.b(pVarF, this);
        return objB == aVar ? aVar : objB;
    }
}

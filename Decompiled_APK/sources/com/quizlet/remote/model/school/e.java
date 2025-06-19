package com.quizlet.remote.model.school;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.remote.service.x;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.set.f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.data.repository.set.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.repository.set.f fVar = this.k;
        if (i == 0) {
            Z.e(obj);
            x xVar = (x) fVar.b;
            this.j = 1;
            obj = xVar.a(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return com.quizlet.data.repository.set.f.a(fVar, (K) obj);
    }
}

package com.quizlet.features.setpage.header.viewmodel;

import androidx.compose.foundation.gestures.S;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            f fVar = this.k;
            J0 j0 = new J0(K1.f(fVar.d.o(fVar.i, fVar.c)), new S(3, 5, null));
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, this.k, f.class, "onStudySetLoaded", "onStudySetLoaded(Lcom/quizlet/data/model/StudySetWithCreatorAndClassification;)V", 4, 3);
            this.j = 1;
            if (e0.i(j0, cVar, this) == aVar) {
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

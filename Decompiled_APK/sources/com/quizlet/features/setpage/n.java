package com.quizlet.features.setpage;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.Y;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ r k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(r rVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = rVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = r.c1;
            r rVar = this.k;
            Y y = ((com.quizlet.features.setpage.studypreview.g) rVar.K.getValue()).m;
            m mVar = new m(rVar, 0);
            this.j = 1;
            if (y.a.b(mVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}

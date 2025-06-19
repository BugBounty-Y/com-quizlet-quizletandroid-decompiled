package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.features.folders.viewmodel.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4323d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ N k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4323d(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4323d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4323d) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            N n = this.k;
            Object objI = e0.i(n.H, new A(n, null), this);
            if (objI != obj2) {
                objI = Unit.a;
            }
            if (objI == obj2) {
                return obj2;
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

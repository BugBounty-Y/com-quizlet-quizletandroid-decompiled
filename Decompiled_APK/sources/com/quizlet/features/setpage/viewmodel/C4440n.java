package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: com.quizlet.features.setpage.viewmodel.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4440n extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C4440n(Function1 function1, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C4440n(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C4440n) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r4v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
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
        Object objInvoke = this.k.invoke(this);
        return objInvoke == aVar ? aVar : objInvoke;
    }
}

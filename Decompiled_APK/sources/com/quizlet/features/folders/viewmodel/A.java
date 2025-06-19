package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ boolean k;
    public final /* synthetic */ N l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        A a = new A(this.l, hVar);
        a.k = ((Boolean) obj).booleanValue();
        return a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((A) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            boolean z = this.k;
            this.j = 1;
            if (N.D(this.l, z, this) == aVar) {
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

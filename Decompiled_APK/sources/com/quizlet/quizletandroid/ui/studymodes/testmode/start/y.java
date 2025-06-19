package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public A j;
    public int k;
    public final /* synthetic */ A l;
    public final /* synthetic */ i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(A a, i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = a;
        this.m = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new y(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        A a;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            A a2 = this.l;
            this.j = a2;
            this.k = 1;
            Object objA = A.A(a2, this.m, this);
            if (objA == aVar) {
                return aVar;
            }
            a = a2;
            obj = objA;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            a = this.j;
            Z.e(obj);
        }
        a.G((c) obj);
        return Unit.a;
    }
}

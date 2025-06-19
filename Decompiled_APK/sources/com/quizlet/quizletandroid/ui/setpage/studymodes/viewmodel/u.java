package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.I;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ y l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(y yVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = yVar;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.l, this.m, hVar);
        uVar.k = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
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
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
        y yVar = this.l;
        I iF = yVar.f;
        if (iF == null) {
            iF = kotlinx.coroutines.E.f(c, null, new t(yVar, this.m, null), 3);
            yVar.f = iF;
        }
        this.j = 1;
        Object objW = iF.w(this);
        return objW == aVar ? aVar : objW;
    }
}

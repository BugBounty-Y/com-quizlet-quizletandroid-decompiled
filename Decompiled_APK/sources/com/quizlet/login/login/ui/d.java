package com.quizlet.login.login.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import com.facebook.login.B;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public InterfaceC0773a0 j;
    public int k;
    public final /* synthetic */ com.quizlet.data.interactor.achievements.f l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.interactor.achievements.f fVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = fVar;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        InterfaceC0773a0 interfaceC0773a0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            InterfaceC0773a0 interfaceC0773a02 = this.m;
            this.j = interfaceC0773a02;
            this.k = 1;
            Object objE = this.l.e(this);
            if (objE == aVar) {
                return aVar;
            }
            interfaceC0773a0 = interfaceC0773a02;
            obj = objE;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            interfaceC0773a0 = this.j;
            Z.e(obj);
        }
        interfaceC0773a0.setValue((B) obj);
        return Unit.a;
    }
}

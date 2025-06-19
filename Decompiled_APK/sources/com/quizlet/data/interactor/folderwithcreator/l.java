package com.quizlet.data.interactor.folderwithcreator;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.collections.K;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ InterfaceC5002j k;
    public /* synthetic */ Throwable l;
    public final /* synthetic */ m m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, long j, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.m = mVar;
        this.n = j;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        l lVar = new l(this.m, this.n, (kotlin.coroutines.h) obj3);
        lVar.k = (InterfaceC5002j) obj;
        lVar.l = (Throwable) obj2;
        return lVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            InterfaceC5002j interfaceC5002j = this.k;
            Throwable th = this.l;
            ((org.slf4j.b) this.m.e).l("Failed to get bookmarked folders for user " + this.n, th);
            K k = K.a;
            this.k = null;
            this.j = 1;
            if (interfaceC5002j.emit(k, this) == aVar) {
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

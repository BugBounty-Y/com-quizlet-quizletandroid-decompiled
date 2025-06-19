package com.quizlet.data.repository.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ InterfaceC4176w0 l;
    public final /* synthetic */ InterfaceC4176w0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(j jVar, InterfaceC4176w0 interfaceC4176w0, InterfaceC4176w0 interfaceC4176w02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = interfaceC4176w0;
        this.m = interfaceC4176w02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            if (j.c(this.k, this.l, this.m, this) == aVar) {
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

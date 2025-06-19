package com.quizlet.quizletandroid.ui.common.ads;

import androidx.compose.animation.C0297y;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.W;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ W l;
    public final /* synthetic */ E m;
    public final /* synthetic */ com.quizlet.ads.c n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(W w, kotlin.coroutines.h hVar, E e, com.quizlet.ads.c cVar) {
        super(2, hVar);
        this.l = w;
        this.m = e;
        this.n = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.l, hVar, this.m, this.n);
        tVar.k = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0297y c0297y = new C0297y((InterfaceC5002j) this.k, this.m, this.n, 8);
            this.j = 1;
            if (this.l.b(c0297y, this) == aVar) {
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

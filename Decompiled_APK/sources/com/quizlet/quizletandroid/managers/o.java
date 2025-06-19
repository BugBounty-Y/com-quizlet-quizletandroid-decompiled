package com.quizlet.quizletandroid.managers;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ u l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        o oVar = new o(this.l, hVar);
        oVar.k = obj;
        return oVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        Object objA;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                u uVar = this.l;
                kotlin.p pVar = kotlin.r.b;
                com.quizlet.shared.usecase.session.b bVar = uVar.q;
                this.j = 1;
                objA = bVar.a(this);
                if (objA == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                objA = ((kotlin.r) obj).a;
            }
            objB = new kotlin.r(objA);
        } catch (Throwable th) {
            kotlin.p pVar2 = kotlin.r.b;
            objB = Z.b(th);
        }
        Throwable thA = kotlin.r.a(objB);
        if (thA != null) {
            timber.log.c.a.e(thA);
        }
        return Unit.a;
    }
}

package com.quizlet.login.magiclink.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.magiclink.data.k;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object hVar;
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String str = this.l;
        j jVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                this.j = 1;
                jVar.b.getClass();
                obj = com.quizlet.qutils.string.c.c(str) ? jVar.A(str, this) : new com.quizlet.login.magiclink.data.h(com.quizlet.login.magiclink.data.e.a);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            hVar = (k) obj;
        } catch (Throwable unused) {
            hVar = new com.quizlet.login.magiclink.data.h(com.quizlet.login.magiclink.data.f.a);
        }
        jVar.getClass();
        if (hVar instanceof com.quizlet.login.magiclink.data.j) {
            jVar.e.h(new com.quizlet.login.magiclink.data.a(str));
        }
        do {
            s0Var = jVar.d;
            value = s0Var.getValue();
        } while (!s0Var.k(value, hVar));
        return Unit.a;
    }
}

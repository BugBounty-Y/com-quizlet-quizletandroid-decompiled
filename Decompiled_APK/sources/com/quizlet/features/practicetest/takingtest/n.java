package com.quizlet.features.practicetest.takingtest;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.practicetest.takingtest.data.A;
import com.quizlet.features.practicetest.takingtest.data.B;
import com.quizlet.features.practicetest.takingtest.data.C;
import com.quizlet.features.practicetest.takingtest.data.D;
import com.quizlet.features.practicetest.takingtest.data.E;
import com.quizlet.features.practicetest.takingtest.data.z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function2 k;
    public final /* synthetic */ Function2 l;
    public final /* synthetic */ Function2 m;
    public final /* synthetic */ Function1 n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ Function0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(Function2 function2, Function2 function22, Function2 function23, Function1 function1, Function0 function0, Function0 function02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function2;
        this.l = function22;
        this.m = function23;
        this.n = function1;
        this.o = function0;
        this.p = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
        nVar.j = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((E) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        E e = (E) this.j;
        if (e instanceof A) {
            A a = (A) e;
            this.k.invoke(a.a, a.b);
        } else if (e instanceof C) {
            C c = (C) e;
            this.l.invoke(c.a, c.b);
        } else if (e instanceof B) {
            this.m.invoke(((B) e).a, com.quizlet.features.infra.models.upgrade.a.x);
        } else {
            boolean z = e instanceof D;
            Function0 function0 = this.o;
            if (z) {
                this.n.invoke(new com.quizlet.ui.models.webpage.g(((D) e).a));
                function0.invoke();
            } else {
                if (!(e instanceof z)) {
                    throw new NoWhenBranchMatchedException();
                }
                if (((z) e).a) {
                    this.p.invoke();
                } else {
                    function0.invoke();
                }
            }
        }
        return Unit.a;
    }
}

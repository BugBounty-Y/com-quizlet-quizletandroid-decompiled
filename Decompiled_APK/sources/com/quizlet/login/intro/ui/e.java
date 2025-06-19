package com.quizlet.login.intro.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.intro.data.l;
import com.quizlet.login.intro.data.m;
import com.quizlet.login.intro.data.n;
import com.quizlet.login.intro.data.o;
import com.quizlet.login.intro.data.p;
import com.quizlet.login.intro.data.q;
import com.quizlet.login.intro.data.r;
import com.quizlet.login.intro.data.s;
import com.quizlet.login.intro.data.t;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function1 o;
    public final /* synthetic */ Function0 p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ Function2 r;
    public final /* synthetic */ Function0 s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function0 function0, Function0 function02, Function1 function1, Function0 function03, Function1 function12, Function0 function04, Function0 function05, Function2 function2, Function0 function06, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function1;
        this.n = function03;
        this.o = function12;
        this.p = function04;
        this.q = function05;
        this.r = function2;
        this.s = function06;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((t) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        t tVar = (t) this.j;
        if (Intrinsics.b(tVar, p.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(tVar, q.a)) {
            this.l.invoke();
        } else if (tVar instanceof s) {
            this.m.invoke(((s) tVar).a);
        } else if (Intrinsics.b(tVar, n.a)) {
            this.n.invoke();
        } else if (tVar instanceof com.quizlet.login.intro.data.k) {
            this.o.invoke(((com.quizlet.login.intro.data.k) tVar).a);
        } else if (tVar instanceof l) {
            this.p.invoke();
        } else if (tVar instanceof r) {
            this.q.invoke();
        } else if (tVar instanceof o) {
            o oVar = (o) tVar;
            this.r.invoke(oVar.a, oVar.b);
        } else {
            if (!(tVar instanceof m)) {
                throw new NoWhenBranchMatchedException();
            }
            this.s.invoke();
        }
        return Unit.a;
    }
}

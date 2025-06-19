package com.quizlet.features.home.composables;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.home.data.j;
import com.quizlet.features.home.data.k;
import com.quizlet.features.home.data.l;
import com.quizlet.features.home.data.m;
import com.quizlet.features.home.data.n;
import com.quizlet.features.home.data.o;
import com.quizlet.features.home.data.p;
import com.quizlet.features.home.data.q;
import com.quizlet.features.home.data.r;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function1 n;
    public final /* synthetic */ Function1 o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function1 q;
    public final /* synthetic */ Function1 r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ Function1 t;
    public final /* synthetic */ Function1 u;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Function0 function0, Function0 function02, Function0 function03, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, Function1 function16, Function1 function17, Function1 function18, h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function03;
        this.n = function1;
        this.o = function12;
        this.p = function13;
        this.q = function14;
        this.r = function15;
        this.s = function16;
        this.t = function17;
        this.u = function18;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        g gVar = new g(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, hVar);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((r) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        r rVar = (r) this.j;
        if (rVar instanceof com.quizlet.features.home.data.h) {
            this.k.invoke();
        } else if (rVar instanceof l) {
            this.l.invoke();
        } else if (rVar instanceof q) {
            this.m.invoke();
        } else if (rVar instanceof j) {
            this.n.invoke(new Long(((j) rVar).a));
        } else if (rVar instanceof k) {
            this.o.invoke(((k) rVar).a);
        } else if (rVar instanceof m) {
            this.p.invoke(((m) rVar).a);
        } else if (rVar instanceof n) {
            this.q.invoke(new Long(((n) rVar).a));
        } else if (rVar instanceof o) {
            this.r.invoke(((o) rVar).a);
        } else if (rVar instanceof com.quizlet.features.home.data.i) {
            this.s.invoke(((com.quizlet.features.home.data.i) rVar).a);
        } else if (rVar instanceof p) {
            this.t.invoke(((p) rVar).a);
        } else {
            if (!(rVar instanceof com.quizlet.features.home.data.g)) {
                throw new NoWhenBranchMatchedException();
            }
            this.u.invoke(((com.quizlet.features.home.data.g) rVar).a);
        }
        return Unit.a;
    }
}

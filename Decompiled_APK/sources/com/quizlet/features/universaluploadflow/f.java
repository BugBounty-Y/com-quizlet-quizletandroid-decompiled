package com.quizlet.features.universaluploadflow;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.universaluploadflow.data.A;
import com.quizlet.features.universaluploadflow.data.B;
import com.quizlet.features.universaluploadflow.data.C;
import com.quizlet.features.universaluploadflow.data.D;
import com.quizlet.features.universaluploadflow.data.E;
import com.quizlet.features.universaluploadflow.data.F;
import com.quizlet.features.universaluploadflow.data.v;
import com.quizlet.features.universaluploadflow.data.w;
import com.quizlet.features.universaluploadflow.data.y;
import com.quizlet.features.universaluploadflow.data.z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ Function1 n;
    public final /* synthetic */ Function1 o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ Function0 r;
    public final /* synthetic */ Function0 s;
    public final /* synthetic */ x t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(Function0 function0, Function0 function02, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function0 function03, Function0 function04, Function0 function05, x xVar, h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function1;
        this.n = function12;
        this.o = function13;
        this.p = function14;
        this.q = function03;
        this.r = function04;
        this.s = function05;
        this.t = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        f fVar = new f(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, hVar);
        fVar.j = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((F) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        F f = (F) this.j;
        if (Intrinsics.b(f, v.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(f, w.a)) {
            this.l.invoke();
        } else if (f instanceof E) {
            this.m.invoke(((E) f).a);
        } else if (f instanceof z) {
            this.n.invoke(((z) f).a);
        } else if (f instanceof com.quizlet.features.universaluploadflow.data.x) {
            this.o.invoke(((com.quizlet.features.universaluploadflow.data.x) f).a);
        } else if (f instanceof B) {
            this.p.invoke(((B) f).a);
        } else if (f instanceof A) {
            this.q.invoke();
        } else if (f instanceof y) {
            this.r.invoke();
        } else if (f instanceof C) {
            this.s.invoke();
        } else {
            if (!Intrinsics.b(f, D.a)) {
                throw new NoWhenBranchMatchedException();
            }
            x.d(this.t);
        }
        return Unit.a;
    }
}

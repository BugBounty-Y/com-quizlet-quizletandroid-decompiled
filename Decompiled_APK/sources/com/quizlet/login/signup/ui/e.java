package com.quizlet.login.signup.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.signup.data.j;
import com.quizlet.login.signup.data.k;
import com.quizlet.login.signup.data.l;
import com.quizlet.login.signup.data.m;
import com.quizlet.login.signup.data.n;
import com.quizlet.login.signup.data.o;
import com.quizlet.login.signup.data.p;
import com.quizlet.login.signup.data.q;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ Function0 p;
    public final /* synthetic */ Function1 q;
    public final /* synthetic */ Function1 r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function1 function1, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function1 function12, Function1 function13, h hVar) {
        super(2, hVar);
        this.k = function1;
        this.l = function0;
        this.m = function02;
        this.n = function03;
        this.o = function04;
        this.p = function05;
        this.q = function12;
        this.r = function13;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        e eVar = new e(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((q) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        q qVar = (q) this.j;
        if (qVar instanceof p) {
            this.k.invoke(((p) qVar).a);
        } else if (Intrinsics.b(qVar, k.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(qVar, o.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(qVar, com.quizlet.login.signup.data.i.a)) {
            this.n.invoke();
        } else if (Intrinsics.b(qVar, j.a)) {
            this.o.invoke();
        } else if (Intrinsics.b(qVar, l.a)) {
            this.p.invoke();
        } else if (qVar instanceof n) {
            this.q.invoke(((n) qVar).a);
        } else {
            if (!(qVar instanceof m)) {
                throw new NoWhenBranchMatchedException();
            }
            this.r.invoke(((m) qVar).a);
        }
        return Unit.a;
    }
}

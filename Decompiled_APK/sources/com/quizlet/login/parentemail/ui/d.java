package com.quizlet.login.parentemail.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.parentemail.data.g;
import com.quizlet.login.parentemail.data.j;
import com.quizlet.login.parentemail.data.k;
import com.quizlet.login.parentemail.data.l;
import com.quizlet.login.parentemail.data.m;
import com.quizlet.login.parentemail.data.n;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function1 o;
    public final /* synthetic */ Function0 p;
    public final /* synthetic */ Function0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Function1 function1, Function0 function0, Function0 function02, Function0 function03, Function1 function12, Function0 function04, Function0 function05, h hVar) {
        super(2, hVar);
        this.k = function1;
        this.l = function0;
        this.m = function02;
        this.n = function03;
        this.o = function12;
        this.p = function04;
        this.q = function05;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((n) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        n nVar = (n) this.j;
        if (nVar instanceof m) {
            this.k.invoke(((m) nVar).a);
        } else if (Intrinsics.b(nVar, g.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(nVar, com.quizlet.login.parentemail.data.h.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(nVar, com.quizlet.login.parentemail.data.i.a)) {
            this.n.invoke();
        } else if (nVar instanceof k) {
            this.o.invoke(((k) nVar).a);
        } else if (Intrinsics.b(nVar, l.a)) {
            this.p.invoke();
        } else {
            if (!Intrinsics.b(nVar, j.a)) {
                throw new NoWhenBranchMatchedException();
            }
            this.q.invoke();
        }
        return Unit.a;
    }
}

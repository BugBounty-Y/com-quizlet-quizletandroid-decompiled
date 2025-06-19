package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ com.quizlet.assembly.compose.toasts.g o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function1 q;
    public final /* synthetic */ Function1 r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ Function1 t;
    public final /* synthetic */ Function2 u;
    public final /* synthetic */ Function2 v;
    public final /* synthetic */ Function2 w;
    public final /* synthetic */ androidx.activity.compose.o x;
    public final /* synthetic */ InterfaceC0773a0 y;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(Function0 function0, Function0 function02, Function0 function03, Function0 function04, com.quizlet.assembly.compose.toasts.g gVar, Function1 function1, Function1 function12, Function1 function13, Function1 function14, Function1 function15, Function2 function2, Function2 function22, Function2 function23, androidx.activity.compose.o oVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function03;
        this.n = function04;
        this.o = gVar;
        this.p = function1;
        this.q = function12;
        this.r = function13;
        this.s = function14;
        this.t = function15;
        this.u = function2;
        this.v = function22;
        this.w = function23;
        this.x = oVar;
        this.y = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C c = new C(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, this.v, this.w, this.x, this.y, hVar);
        c.j = obj;
        return c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((com.quizlet.features.notes.detail.events.p) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.detail.events.p pVar = (com.quizlet.features.notes.detail.events.p) this.j;
        if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.b.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.o.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.g.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.m.a)) {
            this.n.invoke();
        } else if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.j.a)) {
            this.y.setValue(Boolean.TRUE);
        } else if (Intrinsics.b(pVar, com.quizlet.features.notes.detail.events.c.a)) {
            ((L0) this.o.b).setValue(Boolean.TRUE);
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.e) {
            this.p.invoke(((com.quizlet.features.notes.detail.events.e) pVar).a);
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.f) {
            this.q.invoke(new Long(((com.quizlet.features.notes.detail.events.f) pVar).a));
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.h) {
            this.r.invoke(new Long(((com.quizlet.features.notes.detail.events.h) pVar).a));
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.i) {
            this.s.invoke(new Long(((com.quizlet.features.notes.detail.events.i) pVar).a));
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.n) {
            this.t.invoke(new Long(((com.quizlet.features.notes.detail.events.n) pVar).a));
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.l) {
            com.quizlet.features.notes.detail.events.l lVar = (com.quizlet.features.notes.detail.events.l) pVar;
            this.u.invoke(lVar.a, lVar.b);
        } else if (pVar instanceof com.quizlet.features.notes.detail.events.k) {
            this.v.invoke(new Integer(20), ((com.quizlet.features.notes.detail.events.k) pVar).a);
        } else {
            if (!(pVar instanceof com.quizlet.features.notes.detail.events.d)) {
                throw new NoWhenBranchMatchedException();
            }
            this.w.invoke(this.x, new Long(((com.quizlet.features.notes.detail.events.d) pVar).a));
        }
        return Unit.a;
    }
}

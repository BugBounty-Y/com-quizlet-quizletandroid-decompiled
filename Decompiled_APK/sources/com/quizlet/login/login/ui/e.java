package com.quizlet.login.login.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.login.data.l;
import com.quizlet.login.login.data.m;
import com.quizlet.login.login.data.n;
import com.quizlet.login.login.data.o;
import com.quizlet.login.login.data.p;
import com.quizlet.login.login.data.q;
import com.quizlet.login.login.data.r;
import com.quizlet.login.login.data.s;
import com.quizlet.login.login.data.t;
import com.quizlet.login.login.data.u;
import com.quizlet.login.login.data.v;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ Function0 p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ Function2 r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ InterfaceC0773a0 t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, Function0 function06, Function0 function07, Function2 function2, Function1 function1, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function03;
        this.n = function04;
        this.o = function05;
        this.p = function06;
        this.q = function07;
        this.r = function2;
        this.s = function1;
        this.t = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((v) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        v vVar = (v) this.j;
        if (Intrinsics.b(vVar, l.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(vVar, r.a)) {
            this.l.invoke();
        } else if (Intrinsics.b(vVar, t.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(vVar, s.a)) {
            ((Function0) this.t.getValue()).invoke();
        } else if (Intrinsics.b(vVar, n.a)) {
            this.n.invoke();
        } else if (Intrinsics.b(vVar, u.a)) {
            this.o.invoke();
        } else if (Intrinsics.b(vVar, o.a)) {
            this.p.invoke();
        } else if (Intrinsics.b(vVar, m.a)) {
            this.q.invoke();
        } else if (vVar instanceof q) {
            q qVar = (q) vVar;
            this.r.invoke(qVar.a, qVar.b);
        } else {
            if (!(vVar instanceof p)) {
                throw new NoWhenBranchMatchedException();
            }
            this.s.invoke(((p) vVar).a);
        }
        return Unit.a;
    }
}

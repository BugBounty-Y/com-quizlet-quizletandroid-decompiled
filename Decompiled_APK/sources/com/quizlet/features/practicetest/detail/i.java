package com.quizlet.features.practicetest.detail;

import android.content.Context;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.U0;
import com.quizlet.features.practicetest.PracticeTestActivity;
import com.quizlet.features.practicetest.detail.data.A;
import com.quizlet.features.practicetest.detail.data.B;
import com.quizlet.features.practicetest.detail.data.C;
import com.quizlet.features.practicetest.detail.data.D;
import com.quizlet.features.practicetest.detail.data.q;
import com.quizlet.features.practicetest.detail.data.r;
import com.quizlet.features.practicetest.detail.data.s;
import com.quizlet.features.practicetest.detail.data.t;
import com.quizlet.features.practicetest.detail.data.u;
import com.quizlet.features.practicetest.detail.data.v;
import com.quizlet.features.practicetest.detail.data.w;
import com.quizlet.features.practicetest.detail.data.y;
import com.quizlet.features.practicetest.detail.data.z;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ kotlin.jvm.functions.d n;
    public final /* synthetic */ Function2 o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function1 q;
    public final /* synthetic */ Context r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ Function2 t;
    public final /* synthetic */ x u;
    public final /* synthetic */ H0 v;
    public final /* synthetic */ InterfaceC0773a0 w;
    public final /* synthetic */ InterfaceC0773a0 x;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(Function1 function1, Function0 function0, Function1 function12, kotlin.jvm.functions.d dVar, Function2 function2, Function1 function13, Function1 function14, Context context, Function1 function15, Function2 function22, x xVar, H0 h0, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function1;
        this.l = function0;
        this.m = function12;
        this.n = dVar;
        this.o = function2;
        this.p = function13;
        this.q = function14;
        this.r = context;
        this.s = function15;
        this.t = function22;
        this.u = xVar;
        this.v = h0;
        this.w = interfaceC0773a0;
        this.x = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, this.u, this.v, this.w, this.x, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((D) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        D d = (D) this.j;
        if (d instanceof B) {
            this.k.invoke(new Long(((B) d).a));
        } else if (Intrinsics.b(d, t.a)) {
            this.l.invoke();
        } else if (d instanceof y) {
            this.m.invoke(((y) d).a);
        } else if (d instanceof A) {
            A a = (A) d;
            this.n.invoke(a.a, a.b, U0.c, a.c);
        } else if (d instanceof com.quizlet.features.practicetest.detail.data.x) {
            com.quizlet.features.practicetest.detail.data.x xVar = (com.quizlet.features.practicetest.detail.data.x) d;
            this.o.invoke(xVar.a, xVar.b);
        } else {
            boolean z = d instanceof C;
            Function1 function1 = this.p;
            if (z) {
                function1.invoke(((C) d).a);
            } else {
                boolean z2 = d instanceof s;
                Context context = this.r;
                if (z2) {
                    int i = PracticeTestActivity.h;
                    this.q.invoke(L1.c(context, ((s) d).a));
                } else if (d instanceof z) {
                    int i2 = PracticeTestActivity.h;
                    this.s.invoke(L1.c(context, ((z) d).a));
                } else if (d instanceof v) {
                    function1.invoke(new com.quizlet.ui.models.webpage.h(((v) d).a));
                } else if (d instanceof u) {
                    ((u) d).getClass();
                    this.t.invoke("create_practice_test", com.quizlet.features.infra.models.upgrade.a.x);
                } else if (d instanceof r) {
                    if (((r) d).a) {
                        this.v.j(R.string.unable_to_reach_quizlet_msg);
                    }
                    this.w.setValue(Boolean.TRUE);
                } else if (Intrinsics.b(d, q.a)) {
                    this.x.setValue(Boolean.TRUE);
                } else {
                    if (!Intrinsics.b(d, w.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    x.d(this.u);
                }
            }
        }
        return Unit.a;
    }
}

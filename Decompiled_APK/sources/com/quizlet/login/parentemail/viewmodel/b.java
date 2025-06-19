package com.quizlet.login.parentemail.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.common.interactors.data.m;
import com.quizlet.login.common.interactors.data.n;
import com.quizlet.login.common.interactors.data.p;
import com.quizlet.login.common.interactors.data.q;
import com.quizlet.login.common.interactors.data.r;
import com.quizlet.login.common.interactors.data.s;
import com.quizlet.login.common.interactors.data.t;
import com.quizlet.login.common.interactors.data.u;
import com.quizlet.login.common.interactors.data.v;
import com.quizlet.login.common.interactors.data.w;
import com.quizlet.login.common.interactors.data.x;
import com.quizlet.login.common.interactors.data.y;
import com.quizlet.login.common.interactors.data.z;
import com.quizlet.login.parentemail.data.j;
import com.quizlet.login.parentemail.data.k;
import com.quizlet.login.parentemail.data.l;
import com.quizlet.login.parentemail.data.o;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, String str, String str2, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        Object value5;
        Object value6;
        Object value7;
        Object value8;
        Object value9;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var = eVar.d;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, o.a((o) value, true, null, null, 6)));
            this.j = 1;
            obj = eVar.b.d(this.l, this.m, eVar.f, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        z zVar = (z) obj;
        eVar.getClass();
        boolean z = zVar instanceof w;
        s0 s0Var2 = eVar.d;
        if (!z && !(zVar instanceof x)) {
            do {
                value9 = s0Var2.getValue();
            } while (!s0Var2.k(value9, o.a((o) value9, false, null, null, 6)));
        }
        boolean zB = Intrinsics.b(zVar, s.a);
        d0 d0Var = eVar.e;
        if (zB) {
            d0Var.h(com.quizlet.login.parentemail.data.h.a);
        } else {
            boolean zB2 = Intrinsics.b(zVar, w.a);
            Object obj2 = com.quizlet.login.parentemail.data.i.a;
            if (zB2) {
                d0Var.h(obj2);
            } else if (Intrinsics.b(zVar, x.a)) {
                if (!eVar.g) {
                    obj2 = l.a;
                }
                d0Var.h(obj2);
            } else if (zVar instanceof com.quizlet.login.common.interactors.data.l) {
                com.quizlet.login.authentication.data.b bVar = ((com.quizlet.login.common.interactors.data.l) zVar).a;
                if (bVar.a != null) {
                    do {
                        value8 = s0Var2.getValue();
                    } while (!s0Var2.k(value8, o.a((o) value8, false, new com.quizlet.login.authentication.b(bVar.a), null, 5)));
                } else {
                    do {
                        value7 = s0Var2.getValue();
                    } while (!s0Var2.k(value7, o.a((o) value7, false, com.quizlet.login.authentication.h.c, null, 5)));
                }
            } else if (zVar instanceof n) {
                if (((n) zVar).a) {
                    do {
                        value6 = s0Var2.getValue();
                    } while (!s0Var2.k(value6, o.a((o) value6, false, com.quizlet.login.authentication.h.c, null, 5)));
                }
            } else if (Intrinsics.b(zVar, q.a)) {
                do {
                    value5 = s0Var2.getValue();
                } while (!s0Var2.k(value5, o.a((o) value5, false, com.quizlet.login.authentication.i.c, null, 5)));
            } else if (zVar instanceof r) {
                d0Var.h(new k(((r) zVar).a));
            } else if (zVar instanceof com.quizlet.login.common.interactors.data.k) {
                do {
                    value4 = s0Var2.getValue();
                } while (!s0Var2.k(value4, o.a((o) value4, false, com.quizlet.login.authentication.a.c, null, 5)));
            } else if (Intrinsics.b(zVar, m.a)) {
                do {
                    value3 = s0Var2.getValue();
                } while (!s0Var2.k(value3, o.a((o) value3, false, com.quizlet.login.authentication.c.c, null, 5)));
            } else if (Intrinsics.b(zVar, com.quizlet.login.common.interactors.data.o.a)) {
                do {
                    value2 = s0Var2.getValue();
                } while (!s0Var2.k(value2, o.a((o) value2, false, com.quizlet.login.authentication.d.c, null, 5)));
            } else if (Intrinsics.b(zVar, t.a)) {
                d0Var.h(j.a);
            } else {
                if (!(zVar instanceof v) && !(zVar instanceof u) && !Intrinsics.b(zVar, p.a) && !(zVar instanceof y)) {
                    throw new NoWhenBranchMatchedException();
                }
                timber.log.c.a.p(new kotlin.n(e.class.getName() + " " + zVar));
            }
        }
        return Unit.a;
    }
}

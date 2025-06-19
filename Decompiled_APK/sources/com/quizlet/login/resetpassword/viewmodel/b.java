package com.quizlet.login.resetpassword.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.e;
import com.quizlet.login.common.interactors.data.A;
import com.quizlet.login.common.interactors.data.B;
import com.quizlet.login.common.interactors.p;
import com.quizlet.login.resetpassword.data.g;
import com.quizlet.qutils.string.f;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, String str, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        s0 s0Var;
        Object value2;
        f fVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var2 = cVar.c;
            do {
                value = s0Var2.getValue();
                ((g) value).getClass();
            } while (!s0Var2.k(value, new g(null, true)));
            this.j = 1;
            e eVar = cVar.b;
            eVar.getClass();
            obj = E.J((AbstractC5040y) eVar.c, new p(eVar, this.l, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.login.common.interactors.data.C c = (com.quizlet.login.common.interactors.data.C) obj;
        cVar.getClass();
        if (c instanceof A) {
            do {
                s0Var = cVar.c;
                value2 = s0Var.getValue();
                fVar = ((A) c).a;
                ((g) value2).getClass();
            } while (!s0Var.k(value2, new g(fVar, false)));
        } else {
            if (!(c instanceof B)) {
                throw new NoWhenBranchMatchedException();
            }
            cVar.d.h(new com.quizlet.login.resetpassword.data.e(((B) c).a));
        }
        return Unit.a;
    }
}

package com.quizlet.report.viewmodels;

import android.accounts.NetworkErrorException;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.Q0;
import com.quizlet.report.data.d;
import com.quizlet.report.data.o;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ Q0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, Q0 q0, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = q0;
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
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object objI;
        Object value2;
        o oVar;
        d dVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Q0 q0 = this.l;
        c cVar = this.k;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var = cVar.f;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, o.a((o) value, null, null, true, false, false, null, 119)));
            this.j = 1;
            objI = cVar.b.i(cVar.c, q0, cVar.d, this);
            if (objI == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objI = ((r) obj).a;
        }
        Object obj2 = objI;
        p pVar = r.b;
        boolean z = obj2 instanceof q;
        boolean z2 = !z;
        if (!z) {
            cVar.e = q0;
        }
        s0 s0Var2 = cVar.f;
        do {
            value2 = s0Var2.getValue();
            oVar = (o) value2;
            Throwable thA = r.a(obj2);
            if (thA != null) {
                Intrinsics.checkNotNullParameter(thA, "<this>");
                dVar = thA instanceof NetworkErrorException ? com.quizlet.report.data.c.a : com.quizlet.report.data.b.a;
            } else {
                dVar = null;
            }
        } while (!s0Var2.k(value2, o.a(oVar, null, null, false, false, z2, dVar, 23)));
        return Unit.a;
    }
}

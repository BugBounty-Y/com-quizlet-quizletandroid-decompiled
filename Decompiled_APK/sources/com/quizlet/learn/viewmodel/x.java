package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4179x0;
import com.quizlet.generated.enums.O;
import com.quizlet.generated.enums.P;
import com.quizlet.generated.enums.S;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.shared.enums.h k;
    public final /* synthetic */ Integer l;
    public final /* synthetic */ Integer m;
    public final /* synthetic */ G n;
    public final /* synthetic */ Boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(com.quizlet.shared.enums.h hVar, Integer num, Integer num2, G g, Boolean bool, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = num;
        this.m = num2;
        this.n = g;
        this.o = bool;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new x(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            O o = P.Companion;
            com.quizlet.shared.enums.h hVar = this.k;
            o.getClass();
            P pA = O.a(hVar.a);
            int iIntValue = this.l.intValue();
            int iIntValue2 = this.m.intValue();
            G g = this.n;
            C4179x0 c4179x0 = new C4179x0(iIntValue, iIntValue2, pA, new Long(g.Z.u), g.i.getPersonId(), S.UNKNOWN);
            Boolean bool = this.o;
            Intrinsics.d(bool);
            boolean zBooleanValue = bool.booleanValue();
            this.j = 1;
            if (g.t.n(c4179x0, zBooleanValue, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

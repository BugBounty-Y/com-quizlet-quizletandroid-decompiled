package com.quizlet.features.practicetest.takingtest.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.practicetest.takingtest.data.F;
import com.quizlet.features.practicetest.takingtest.data.H;
import com.quizlet.features.practicetest.takingtest.data.K;
import com.quizlet.features.practicetest.takingtest.data.N;
import com.quizlet.features.practicetest.takingtest.data.w;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;
    public final /* synthetic */ w l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(l lVar, w wVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
        this.l = wVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        l lVar = this.k;
        s0 s0Var = lVar.k;
        if (i == 0) {
            Z.e(obj);
            ArrayList arrayList = new ArrayList();
            w wVar = this.l;
            if (wVar.b) {
                arrayList.add(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER);
            }
            if (wVar.c) {
                arrayList.add(EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE);
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(((EnumC4533y0) it2.next()).a());
            }
            String strC = lVar.C();
            lVar.e.c(wVar.a, arrayList2, lVar.j, strC, "test_setup_modal");
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, H.a));
            String strC2 = lVar.C();
            this.j = 1;
            obj = lVar.c.a(strC2, wVar.a, arrayList, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        K k = (K) obj;
        lVar.b.c(k.a, "practiceTestId");
        F f = k.b;
        N n = f.e;
        if (n != null) {
            lVar.D(n);
        }
        do {
            value2 = s0Var.getValue();
        } while (!s0Var.k(value2, f));
        return Unit.a;
    }
}

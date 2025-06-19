package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.z;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.s;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.u;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ t k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.k, hVar);
        cVar.j = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.h) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        s0 s0Var;
        Object value;
        int iA;
        int i;
        int i2;
        s0 s0Var2;
        Object value2;
        ArrayList arrayListK;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.h testResultsData = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.h) this.j;
        t tVar = this.k;
        tVar.getClass();
        Intrinsics.checkNotNullParameter(testResultsData, "testResultsData");
        tVar.o = testResultsData.i;
        tVar.p = testResultsData.g;
        double d = testResultsData.h;
        int iA2 = kotlin.math.c.a(d);
        tVar.r = iA2;
        if (tVar.n) {
            tVar.l.g();
        } else {
            IntRange intRange = u.a;
            int i3 = intRange.a;
            if (iA2 > intRange.b || i3 > iA2) {
                IntRange intRange2 = u.b;
                int i4 = intRange2.a;
                if (iA2 <= intRange2.b && i4 <= iA2) {
                    tVar.n = true;
                    E.A(p0.j(tVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.p(tVar, null), 3);
                }
            } else {
                tVar.n = true;
                E.A(p0.j(tVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.o(tVar, null), 3);
            }
        }
        E.A(p0.j(tVar), null, null, new s(tVar.r, tVar, null), 3);
        ArrayList arrayList = testResultsData.j;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (!((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g) next).b.a) {
                arrayList2.add(next);
            }
        }
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            arrayList3.add(Long.valueOf(((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g) it3.next()).a.a().b));
        }
        tVar.q = arrayList3;
        int i5 = tVar.r;
        StudiableMeteringData studiableMeteringData = tVar.o;
        boolean z = studiableMeteringData != null ? studiableMeteringData.f : false;
        StudiableMeteringData studiableMeteringData2 = tVar.p;
        E.A(p0.j(tVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.l(tVar, i5, z, studiableMeteringData2 != null ? studiableMeteringData2.f : false, arrayList3, null), 3);
        do {
            s0Var = tVar.g;
            value = s0Var.getValue();
            iA = kotlin.math.c.a(d);
            i = testResultsData.e;
            i2 = testResultsData.f;
        } while (!s0Var.k(value, new I(A.b(new z(iA, i2, i - i2)))));
        do {
            s0Var2 = tVar.h;
            value2 = s0Var2.getValue();
            ArrayList arrayList4 = new ArrayList(C.q(arrayList, 10));
            Iterator it4 = arrayList.iterator();
            while (it4.hasNext()) {
                arrayList4.add(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.t((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.g) it4.next()));
            }
            arrayListK = B.k(com.quizlet.quizletandroid.ui.studymodes.testmode.models.u.a);
            arrayListK.addAll(arrayList4);
        } while (!s0Var2.k(value2, new H(arrayListK)));
        return Unit.a;
    }
}

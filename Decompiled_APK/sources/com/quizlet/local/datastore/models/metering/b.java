package com.quizlet.local.datastore.models.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.google.protobuf.AbstractC4027v;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.o2;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public j j;
    public int k;
    public final /* synthetic */ com.quizlet.data.repository.folderset.c l;
    public final /* synthetic */ InterfaceC4176w0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.folderset.c cVar, InterfaceC4176w0 interfaceC4176w0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = cVar;
        this.m = interfaceC4176w0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        d dVar;
        j jVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.folderset.c cVar = this.l;
            j jVar2 = (j) cVar.c;
            i iVar = (i) cVar.b;
            InterfaceC4176w0 data = this.m;
            Intrinsics.checkNotNullParameter(data, "data");
            if (data instanceof o2) {
                c cVarJ = d.J();
                cVarJ.k();
                d.x((d) cVarJ.b, -1);
                cVarJ.k();
                d.A((d) cVarJ.b, -1);
                o2 o2Var = (o2) data;
                int iA = o2Var.a.a();
                cVarJ.k();
                d.w((d) cVarJ.b, iA);
                cVarJ.k();
                d.B((d) cVarJ.b, o2Var.c);
                int iA2 = o2Var.d.a();
                cVarJ.k();
                d.y((d) cVarJ.b, iA2);
                Long l = o2Var.b;
                if (l != null) {
                    long jLongValue = l.longValue();
                    cVarJ.k();
                    d.z((d) cVarJ.b, jLongValue);
                }
                AbstractC4027v abstractC4027vH = cVarJ.h();
                Intrinsics.checkNotNullExpressionValue(abstractC4027vH, "build(...)");
                dVar = (d) abstractC4027vH;
            } else {
                if (!(data instanceof C4179x0)) {
                    throw new NoWhenBranchMatchedException();
                }
                c cVarJ2 = d.J();
                C4179x0 c4179x0 = (C4179x0) data;
                int i2 = c4179x0.a;
                cVarJ2.k();
                d.x((d) cVarJ2.b, i2);
                cVarJ2.k();
                d.A((d) cVarJ2.b, c4179x0.b);
                int iA3 = c4179x0.c.a();
                cVarJ2.k();
                d.w((d) cVarJ2.b, iA3);
                cVarJ2.k();
                d.B((d) cVarJ2.b, c4179x0.e);
                int iA4 = c4179x0.f.a();
                cVarJ2.k();
                d.y((d) cVarJ2.b, iA4);
                Long l2 = c4179x0.d;
                if (l2 != null) {
                    long jLongValue2 = l2.longValue();
                    cVarJ2.k();
                    d.z((d) cVarJ2.b, jLongValue2);
                }
                AbstractC4027v abstractC4027vH2 = cVarJ2.h();
                Intrinsics.checkNotNullExpressionValue(abstractC4027vH2, "build(...)");
                dVar = (d) abstractC4027vH2;
            }
            this.j = jVar2;
            this.k = 1;
            obj = iVar.c(dVar, this);
            if (obj == aVar) {
                return aVar;
            }
            jVar = jVar2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            jVar = this.j;
            Z.e(obj);
        }
        jVar.getClass();
        return j.d((d) obj);
    }
}

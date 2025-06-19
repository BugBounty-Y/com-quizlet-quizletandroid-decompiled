package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public o j;
    public o k;
    public int l;
    public final /* synthetic */ o m;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(o oVar, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = oVar;
        this.n = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        o oVar;
        Object obj2;
        o oVar2;
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar = this.n;
        if (i == 0) {
            Z.e(obj);
            o oVar3 = this.m;
            this.j = oVar3;
            this.k = oVar3;
            this.l = 1;
            Object objA = oVar3.c.a(eVar, this);
            if (objA == aVar) {
                return aVar;
            }
            oVar = oVar3;
            obj2 = objA;
            oVar2 = oVar;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            oVar = this.k;
            oVar2 = this.j;
            Z.e(obj);
            obj2 = ((r) obj).a;
        }
        oVar.getClass();
        p pVar = r.b;
        if (!(obj2 instanceof q)) {
            oVar.m = eVar;
            oVar.g.n();
            E.A(p0.j(oVar), null, null, new l(oVar, eVar, null), 3);
            oVar.A(oVar.m);
        }
        oVar2.getClass();
        if (r.a(obj2) != null) {
            do {
                s0Var = oVar2.h;
                value = s0Var.getValue();
            } while (!s0Var.k(value, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p((List) o.C(((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q) value).getResults(), eVar, false), com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b, false, 28)));
        }
        return Unit.a;
    }
}

package com.quizlet.edgy.ui.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.school.exceptions.SchoolNotFoundException;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ com.quizlet.edgy.ui.recyclerview.adapter.g l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(M m, com.quizlet.edgy.ui.recyclerview.adapter.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws SchoolNotFoundException {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.edgy.ui.recyclerview.adapter.g gVar = this.l;
        M m = this.k;
        if (i == 0) {
            Z.e(obj);
            if (m.k == null) {
                throw new SchoolNotFoundException("School cannot be null on course selection.");
            }
            do {
                s0Var = m.p;
                value = s0Var.getValue();
            } while (!s0Var.k(value, C4205f.a));
            m.j.j("edgy_data_course_data_submitted", "submit", "edgy_data", true);
            long j = gVar.a;
            com.quizlet.edgy.ui.recyclerview.adapter.i iVar = m.k;
            long j2 = iVar != null ? iVar.a : 0L;
            this.j = 1;
            if (m.g.f(j, j2, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        m.j.j("edgy_data_school_screen_added_new_course", "submit", "edgy_data", true);
        ArrayList arrayList = m.o;
        Intrinsics.checkNotNullParameter(gVar, "<this>");
        arrayList.add(0, new com.quizlet.edgy.ui.recyclerview.adapter.d(gVar.a, gVar.c, gVar.b));
        m.D();
        return Unit.a;
    }
}

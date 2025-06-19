package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P6;
import com.quizlet.data.model.School;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ EdgyAddSchoolManuallyFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddSchoolManuallyFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.k, hVar);
        uVar.j = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((com.quizlet.edgy.ui.viewmodel.t) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.edgy.ui.viewmodel.t tVar = (com.quizlet.edgy.ui.viewmodel.t) this.j;
        if (tVar == null) {
            throw new NoWhenBranchMatchedException();
        }
        EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = this.k;
        com.quizlet.edgy.ui.viewmodel.M m = (com.quizlet.edgy.ui.viewmodel.M) edgyAddSchoolManuallyFragment.l.getValue();
        m.getClass();
        School school = tVar.a;
        Intrinsics.checkNotNullParameter(school, "school");
        com.quizlet.edgy.ui.recyclerview.adapter.i searchSchoolItem = P6.a(school);
        Intrinsics.checkNotNullParameter(searchSchoolItem, "searchSchoolItem");
        kotlinx.coroutines.E.A(p0.j(m), m.u, null, new com.quizlet.edgy.ui.viewmodel.K(searchSchoolItem, m, null), 2);
        edgyAddSchoolManuallyFragment.getParentFragmentManager().V();
        return Unit.a;
    }
}

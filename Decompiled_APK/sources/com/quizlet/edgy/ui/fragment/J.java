package com.quizlet.edgy.ui.fragment;

import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ AbstractC1136h0 k;
    public final /* synthetic */ EdgyModalFragment l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(AbstractC1136h0 abstractC1136h0, EdgyModalFragment edgyModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = abstractC1136h0;
        this.l = edgyModalFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        J j = new J(this.k, this.l, hVar);
        j.j = obj;
        return j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((com.quizlet.edgy.ui.viewmodel.y) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.edgy.ui.viewmodel.y yVar = (com.quizlet.edgy.ui.viewmodel.y) this.j;
        boolean zB = Intrinsics.b(yVar, com.quizlet.edgy.ui.viewmodel.x.c);
        AbstractC1136h0 abstractC1136h0 = this.k;
        if (zB) {
            EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = new EdgyAddSchoolManuallyFragment();
            abstractC1136h0.getClass();
            C1121a c1121a = new C1121a(abstractC1136h0);
            String str = EdgyAddSchoolManuallyFragment.o;
            c1121a.i(R.id.contentFragment, edgyAddSchoolManuallyFragment, str, 1);
            c1121a.d(str);
            new Integer(c1121a.h(false, true));
        } else if (Intrinsics.b(yVar, com.quizlet.edgy.ui.viewmodel.x.b)) {
            EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment = new EdgyAddCourseManuallyFragment();
            abstractC1136h0.getClass();
            C1121a c1121a2 = new C1121a(abstractC1136h0);
            String str2 = EdgyAddCourseManuallyFragment.m;
            c1121a2.i(R.id.contentFragment, edgyAddCourseManuallyFragment, str2, 1);
            c1121a2.d(str2);
            new Integer(c1121a2.h(false, true));
        } else {
            if (!Intrinsics.b(yVar, com.quizlet.edgy.ui.viewmodel.x.a)) {
                throw new NoWhenBranchMatchedException();
            }
            this.l.H(false, false);
            Unit unit = Unit.a;
        }
        return Unit.a;
    }
}

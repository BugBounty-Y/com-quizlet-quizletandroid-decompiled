package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O6;
import com.quizlet.data.model.Course;
import com.quizlet.edgy.ui.viewmodel.C4200a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.fragment.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4187a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ EdgyAddCourseManuallyFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4187a(EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddCourseManuallyFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4187a c4187a = new C4187a(this.k, hVar);
        c4187a.j = obj;
        return c4187a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4187a) create((C4200a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C4200a c4200a = (C4200a) this.j;
        if (c4200a == null) {
            throw new NoWhenBranchMatchedException();
        }
        EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment = this.k;
        com.quizlet.edgy.ui.viewmodel.M m = (com.quizlet.edgy.ui.viewmodel.M) edgyAddCourseManuallyFragment.l.getValue();
        m.getClass();
        Course course = c4200a.a;
        Intrinsics.checkNotNullParameter(course, "course");
        com.quizlet.edgy.ui.recyclerview.adapter.g searchCourseItem = O6.b(course);
        Intrinsics.checkNotNullParameter(searchCourseItem, "searchCourseItem");
        kotlinx.coroutines.E.A(p0.j(m), m.u, null, new com.quizlet.edgy.ui.viewmodel.J(m, searchCourseItem, null), 2);
        edgyAddCourseManuallyFragment.getParentFragmentManager().V();
        return Unit.a;
    }
}

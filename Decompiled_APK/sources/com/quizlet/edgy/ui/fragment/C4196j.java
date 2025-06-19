package com.quizlet.edgy.ui.fragment;

import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.fragment.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4196j implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ EdgyAddSchoolAndCoursesFragment b;

    public /* synthetic */ C4196j(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, int i) {
        this.a = i;
        this.b = edgyAddSchoolAndCoursesFragment;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.edgy.ui.recyclerview.adapter.g searchCourseItem = (com.quizlet.edgy.ui.recyclerview.adapter.g) obj;
                String str = EdgyAddSchoolAndCoursesFragment.u;
                Intrinsics.checkNotNullParameter(searchCourseItem, "it");
                com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                mU.getClass();
                Intrinsics.checkNotNullParameter(searchCourseItem, "searchCourseItem");
                kotlinx.coroutines.E.A(p0.j(mU), mU.u, null, new com.quizlet.edgy.ui.viewmodel.J(mU, searchCourseItem, null), 2);
                break;
            case 1:
                com.quizlet.edgy.ui.recyclerview.adapter.i searchSchoolItem = (com.quizlet.edgy.ui.recyclerview.adapter.i) obj;
                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                Intrinsics.checkNotNullParameter(searchSchoolItem, "it");
                com.quizlet.edgy.ui.viewmodel.M mU2 = edgyAddSchoolAndCoursesFragment.U();
                mU2.getClass();
                Intrinsics.checkNotNullParameter(searchSchoolItem, "searchSchoolItem");
                kotlinx.coroutines.E.A(p0.j(mU2), mU2.u, null, new com.quizlet.edgy.ui.viewmodel.K(searchSchoolItem, mU2, null), 2);
                break;
            default:
                com.quizlet.edgy.ui.recyclerview.adapter.d courseSelectedItem = (com.quizlet.edgy.ui.recyclerview.adapter.d) obj;
                String str3 = EdgyAddSchoolAndCoursesFragment.u;
                Intrinsics.checkNotNullParameter(courseSelectedItem, "it");
                com.quizlet.edgy.ui.viewmodel.M mU3 = edgyAddSchoolAndCoursesFragment.U();
                mU3.getClass();
                Intrinsics.checkNotNullParameter(courseSelectedItem, "courseSelectedItem");
                if (!CollectionsKt.w0(mU3.o).isEmpty()) {
                    kotlinx.coroutines.E.A(p0.j(mU3), mU3.u, null, new com.quizlet.edgy.ui.viewmodel.A(mU3, courseSelectedItem, null), 2);
                }
                break;
        }
        return Unit.a;
    }
}

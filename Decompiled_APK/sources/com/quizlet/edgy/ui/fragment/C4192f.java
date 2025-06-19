package com.quizlet.edgy.ui.fragment;

import android.content.Context;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.C1370i;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.fragment.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4192f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ EdgyAddSchoolAndCoursesFragment b;

    public /* synthetic */ C4192f(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, int i) {
        this.a = i;
        this.b = edgyAddSchoolAndCoursesFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int i = 3;
        int i2 = 1;
        int i3 = 0;
        int i4 = 2;
        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.b;
        switch (this.a) {
            case 0:
                String str = EdgyAddSchoolAndCoursesFragment.u;
                com.quizlet.baserecyclerview.decoration.c cVar = new com.quizlet.baserecyclerview.decoration.c(edgyAddSchoolAndCoursesFragment.getContext(), 1, 0, com.quizlet.baserecyclerview.decoration.b.Z0);
                Context contextRequireContext = edgyAddSchoolAndCoursesFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                cVar.a.setColor(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.dividerColor));
                return cVar;
            case 1:
                String str2 = EdgyAddSchoolAndCoursesFragment.u;
                edgyAddSchoolAndCoursesFragment.U().C();
                return Unit.a;
            case 2:
                String str3 = EdgyAddSchoolAndCoursesFragment.u;
                com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                mU.getClass();
                kotlinx.coroutines.E.A(p0.j(mU), null, null, new com.quizlet.edgy.ui.viewmodel.E(mU, null), 3);
                return Unit.a;
            case 3:
                String str4 = EdgyAddSchoolAndCoursesFragment.u;
                com.quizlet.edgy.ui.viewmodel.M mU2 = edgyAddSchoolAndCoursesFragment.U();
                mU2.getClass();
                kotlinx.coroutines.E.A(p0.j(mU2), null, null, new com.quizlet.edgy.ui.viewmodel.D(mU2, null), 3);
                return Unit.a;
            case 4:
                String str5 = EdgyAddSchoolAndCoursesFragment.u;
                return new com.quizlet.edgy.ui.recyclerview.adapter.h(new C4196j(edgyAddSchoolAndCoursesFragment, i2));
            case 5:
                String str6 = EdgyAddSchoolAndCoursesFragment.u;
                return new com.quizlet.edgy.ui.recyclerview.adapter.f(new C4196j(edgyAddSchoolAndCoursesFragment, i3));
            case 6:
                String str7 = EdgyAddSchoolAndCoursesFragment.u;
                return new com.quizlet.edgy.ui.recyclerview.adapter.c(new C4196j(edgyAddSchoolAndCoursesFragment, i4));
            case 7:
                String str8 = EdgyAddSchoolAndCoursesFragment.u;
                return new com.quizlet.edgy.ui.recyclerview.adapter.b(new C4192f(edgyAddSchoolAndCoursesFragment, i4));
            case 8:
                String str9 = EdgyAddSchoolAndCoursesFragment.u;
                return new com.quizlet.edgy.ui.recyclerview.adapter.a(new C4192f(edgyAddSchoolAndCoursesFragment, i));
            case 9:
                String str10 = EdgyAddSchoolAndCoursesFragment.u;
                return new C1370i((com.quizlet.edgy.ui.recyclerview.adapter.h) edgyAddSchoolAndCoursesFragment.l.getValue(), (com.quizlet.edgy.ui.recyclerview.adapter.b) edgyAddSchoolAndCoursesFragment.o.getValue());
            case 10:
                String str11 = EdgyAddSchoolAndCoursesFragment.u;
                return new C1370i((com.quizlet.edgy.ui.recyclerview.adapter.f) edgyAddSchoolAndCoursesFragment.m.getValue(), (com.quizlet.edgy.ui.recyclerview.adapter.a) edgyAddSchoolAndCoursesFragment.p.getValue());
            default:
                return new C1370i((com.quizlet.edgy.ui.recyclerview.adapter.e) edgyAddSchoolAndCoursesFragment.k.getValue(), (com.quizlet.edgy.ui.recyclerview.adapter.h) edgyAddSchoolAndCoursesFragment.l.getValue());
        }
    }
}

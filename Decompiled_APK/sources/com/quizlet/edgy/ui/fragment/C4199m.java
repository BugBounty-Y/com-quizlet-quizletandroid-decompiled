package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* renamed from: com.quizlet.edgy.ui.fragment.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4199m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ EdgyAddSchoolAndCoursesFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4199m(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddSchoolAndCoursesFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4199m(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4199m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = EdgyAddSchoolAndCoursesFragment.u;
            EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.k;
            s0 s0Var = edgyAddSchoolAndCoursesFragment.U().p;
            C4198l c4198l = new C4198l(edgyAddSchoolAndCoursesFragment, null);
            this.j = 1;
            if (e0.i(s0Var, c4198l, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}

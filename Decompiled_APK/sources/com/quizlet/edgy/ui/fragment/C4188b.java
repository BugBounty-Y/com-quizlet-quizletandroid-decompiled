package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.edgy.ui.viewmodel.C4204e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.edgy.ui.fragment.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4188b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ EdgyAddCourseManuallyFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4188b(EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddCourseManuallyFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4188b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4188b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = EdgyAddCourseManuallyFragment.m;
            EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment = this.k;
            d0 d0Var = ((C4204e) edgyAddCourseManuallyFragment.k.getValue()).d;
            C4187a c4187a = new C4187a(edgyAddCourseManuallyFragment, null);
            this.j = 1;
            if (e0.i(d0Var, c4187a, this) == aVar) {
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

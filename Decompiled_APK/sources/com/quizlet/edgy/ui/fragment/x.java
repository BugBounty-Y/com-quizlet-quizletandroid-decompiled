package com.quizlet.edgy.ui.fragment;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ boolean j;
    public final /* synthetic */ EdgyAddSchoolManuallyFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = edgyAddSchoolManuallyFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x xVar = new x(this.k, hVar);
        xVar.j = ((Boolean) obj).booleanValue();
        return xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((x) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        boolean z = this.j;
        String str = EdgyAddSchoolManuallyFragment.o;
        EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = this.k;
        AssemblyInputLayout stateDropdown = ((com.quizlet.edgy.databinding.c) edgyAddSchoolManuallyFragment.J()).g;
        Intrinsics.checkNotNullExpressionValue(stateDropdown, "stateDropdown");
        stateDropdown.setVisibility(z ? 0 : 8);
        edgyAddSchoolManuallyFragment.V(z);
        return Unit.a;
    }
}

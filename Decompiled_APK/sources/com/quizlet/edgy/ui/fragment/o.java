package com.quizlet.edgy.ui.fragment;

import android.os.Bundle;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.ConfirmationModalFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ EdgyAddSchoolAndCoursesFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = edgyAddSchoolAndCoursesFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        String str = EdgyAddSchoolAndCoursesFragment.u;
        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.j;
        String title = edgyAddSchoolAndCoursesFragment.getString(R.string.remove_school_dialog_title);
        Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
        String description = edgyAddSchoolAndCoursesFragment.getString(R.string.remove_school_dialog_description);
        Intrinsics.checkNotNullExpressionValue(description, "getString(...)");
        String actionText = edgyAddSchoolAndCoursesFragment.getString(R.string.remove_school_dialog_button_text);
        Intrinsics.checkNotNullExpressionValue(actionText, "getString(...)");
        String cancelText = edgyAddSchoolAndCoursesFragment.getString(R.string.cancel);
        Intrinsics.checkNotNullExpressionValue(cancelText, "getString(...)");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(actionText, "actionText");
        Intrinsics.checkNotNullParameter(cancelText, "cancelText");
        ConfirmationModalFragment confirmationModalFragment = new ConfirmationModalFragment();
        Bundle bundle = new Bundle();
        bundle.putString("ARG_TITLE", title);
        bundle.putString("ARG_DESCRIPTION", description);
        bundle.putString("ARG_ACTION_TEXT", actionText);
        bundle.putString("ARG_CANCEL_TEXT", cancelText);
        confirmationModalFragment.setArguments(bundle);
        confirmationModalFragment.F = new C4192f(edgyAddSchoolAndCoursesFragment, 1);
        confirmationModalFragment.O(edgyAddSchoolAndCoursesFragment.getChildFragmentManager(), "ConfirmationModalFragment");
        return Unit.a;
    }
}

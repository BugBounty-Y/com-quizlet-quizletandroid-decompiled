package com.quizlet.edgy.ui.fragment;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.InterfaceC1128d0;
import androidx.lifecycle.p0;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class EdgyModalFragment extends Hilt_EdgyModalFragment {
    public static final String L;
    public final kotlin.u I = kotlin.l.b(new com.braze.requests.framework.o(this, 27));
    public final com.quizlet.uicommon.ui.common.dialogs.b J = com.quizlet.uicommon.ui.common.dialogs.b.b;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e K;

    static {
        Intrinsics.checkNotNullExpressionValue("EdgyModalFragment", "getSimpleName(...)");
        L = "EdgyModalFragment";
    }

    public EdgyModalFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 11), 12));
        this.K = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.edgy.ui.viewmodel.M.class), new C4062f(kVarA, 10), new androidx.credentials.playservices.controllers.BeginSignIn.d(19, this, kVarA), new C4062f(kVarA, 11));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Window window = dialogK.getWindow();
        if (window != null) {
            window.setSoftInputMode(16);
        }
        return dialogK;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, final AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        fragmentManager.o.add(new InterfaceC1128d0() { // from class: com.quizlet.edgy.ui.fragment.I
            @Override // androidx.fragment.app.InterfaceC1128d0
            public final void a() {
                String str = EdgyModalFragment.L;
                List listF = fragmentManager.c.f();
                Intrinsics.checkNotNullExpressionValue(listF, "getFragments(...)");
                Fragment fragment = (Fragment) CollectionsKt.V(listF);
                EdgyModalFragment edgyModalFragment = this.a;
                edgyModalFragment.getClass();
                String string = fragment instanceof EdgyAddSchoolManuallyFragment ? edgyModalFragment.getResources().getString(R.string.edgy_flow_add_new_school) : fragment instanceof EdgyAddCourseManuallyFragment ? edgyModalFragment.getResources().getString(R.string.edgy_flow_add_new_course) : edgyModalFragment.W();
                QTextView qTextView = ((com.quizlet.quizletandroid.ui.common.databinding.a) edgyModalFragment.P()).e;
                qTextView.setText(string);
                qTextView.setVisibility(string == null ? 8 : 0);
            }
        });
        EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = new EdgyAddSchoolAndCoursesFragment();
        C1121a c1121a = new C1121a(fragmentManager);
        c1121a.l(R.id.contentFragment, edgyAddSchoolAndCoursesFragment, EdgyAddSchoolAndCoursesFragment.u);
        c1121a.g();
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new L(fragmentManager, this, null), 3);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final com.quizlet.uicommon.ui.common.dialogs.b S() {
        return this.J;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final String W() {
        return (String) this.I.getValue();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        ((com.quizlet.edgy.ui.viewmodel.M) this.K.getValue()).j.j("edgy_data_modal_exited", "exit", "edgy_data_collect_courses_screen", false);
        if (requireArguments().getBoolean("ARG_SET_RESULT_ON_DISMISS", false)) {
            getParentFragmentManager().g0(new Bundle(0), "edgyCollectionRequest");
        }
        super.onDismiss(dialog);
    }
}

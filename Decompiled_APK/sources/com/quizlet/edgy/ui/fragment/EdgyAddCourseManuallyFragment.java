package com.quizlet.edgy.ui.fragment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.edgy.ui.viewmodel.C4204e;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class EdgyAddCourseManuallyFragment extends Hilt_EdgyAddCourseManuallyFragment<com.quizlet.edgy.databinding.a> {
    public static final String m;
    public com.quizlet.edgy.utils.d j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;

    static {
        Intrinsics.checkNotNullExpressionValue("EdgyAddCourseManuallyFragment", "getSimpleName(...)");
        m = "EdgyAddCourseManuallyFragment";
    }

    public EdgyAddCourseManuallyFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 7), 8));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(C4204e.class), new C4062f(kVarA, 6), new androidx.credentials.playservices.controllers.BeginSignIn.d(17, this, kVarA), new C4062f(kVarA, 7));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.edgy.ui.viewmodel.M.class), new C4190d(this, 0), new C4190d(this, 2), new C4190d(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_add_course_manually, viewGroup, false);
        int i = R.id.btnSaveCourse;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.btnSaveCourse, viewInflate);
        if (qButton != null) {
            i = R.id.courseCodeEditText;
            AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) AbstractC3375o2.c(R.id.courseCodeEditText, viewInflate);
            if (assemblyInputEditText != null) {
                i = R.id.courseCodeInputLayout;
                if (((AssemblyInputLayout) AbstractC3375o2.c(R.id.courseCodeInputLayout, viewInflate)) != null) {
                    i = R.id.courseNameEditText;
                    AssemblyInputEditText assemblyInputEditText2 = (AssemblyInputEditText) AbstractC3375o2.c(R.id.courseNameEditText, viewInflate);
                    if (assemblyInputEditText2 != null) {
                        i = R.id.courseNameInputLayout;
                        if (((AssemblyInputLayout) AbstractC3375o2.c(R.id.courseNameInputLayout, viewInflate)) != null) {
                            com.quizlet.edgy.databinding.a aVar = new com.quizlet.edgy.databinding.a((ScrollView) viewInflate, qButton, assemblyInputEditText, assemblyInputEditText2);
                            Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                            return aVar;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.edgy.utils.d T() {
        com.quizlet.edgy.utils.d dVar = this.j;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("emptyFieldValidationTextWatcher");
        throw null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        T().b = ((com.quizlet.edgy.databinding.a) J()).b;
        com.quizlet.edgy.utils.d dVarT = T();
        com.quizlet.edgy.utils.e eVar = com.quizlet.edgy.utils.e.b;
        Intrinsics.checkNotNullParameter(eVar, "<set-?>");
        dVarT.d = eVar;
        com.quizlet.edgy.utils.d dVarT2 = T();
        com.quizlet.edgy.databinding.a aVar = (com.quizlet.edgy.databinding.a) J();
        dVarT2.c = kotlin.collections.B.j(aVar.c, ((com.quizlet.edgy.databinding.a) J()).d);
        dVarT2.e();
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new C4189c(this, null), 3);
        com.quizlet.edgy.databinding.a aVar2 = (com.quizlet.edgy.databinding.a) J();
        aVar2.b.setOnClickListener(new com.braze.ui.inappmessage.d(this, 13));
        aVar2.c.addTextChangedListener(T());
        aVar2.d.addTextChangedListener(T());
    }
}

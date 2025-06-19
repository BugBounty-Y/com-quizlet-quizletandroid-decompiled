package com.quizlet.explanations.feedback.ui.fragments;

import android.content.res.Resources;
import android.os.Bundle;
import android.text.Editable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.RadioGroup;
import androidx.appcompat.widget.U0;
import androidx.constraintlayout.helper.widget.Flow;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X6;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.assembly.widgets.radio.AssemblyRadioButton;
import com.quizlet.data.model.W;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes2.dex */
public final class ReportThisContentFragment extends Hilt_ReportThisContentFragment<com.quizlet.explanations.databinding.j> {
    public static final String k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.feedback.viewmodel.a.class), new h(this, 0), new h(this, 2), new h(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("ReportThisContentFragment", "getSimpleName(...)");
        k = "ReportThisContentFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_report_this_content, viewGroup, false);
        int i = R.id.cancelButton;
        AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.cancelButton, viewInflate);
        if (assemblySecondaryButton != null) {
            i = R.id.contentRadioGroup;
            RadioGroup radioGroup = (RadioGroup) AbstractC3375o2.c(R.id.contentRadioGroup, viewInflate);
            if (radioGroup != null) {
                i = R.id.optionFlow;
                if (((Flow) AbstractC3375o2.c(R.id.optionFlow, viewInflate)) != null) {
                    i = R.id.otherEditText;
                    AssemblyInputLayout assemblyInputLayout = (AssemblyInputLayout) AbstractC3375o2.c(R.id.otherEditText, viewInflate);
                    if (assemblyInputLayout != null) {
                        i = R.id.reportOptionOne;
                        if (((AssemblyRadioButton) AbstractC3375o2.c(R.id.reportOptionOne, viewInflate)) != null) {
                            i = R.id.reportOptionOther;
                            if (((AssemblyRadioButton) AbstractC3375o2.c(R.id.reportOptionOther, viewInflate)) != null) {
                                i = R.id.reportOptionTwo;
                                if (((AssemblyRadioButton) AbstractC3375o2.c(R.id.reportOptionTwo, viewInflate)) != null) {
                                    i = R.id.reportTitle;
                                    if (((QTextView) AbstractC3375o2.c(R.id.reportTitle, viewInflate)) != null) {
                                        i = R.id.submitButton;
                                        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.submitButton, viewInflate);
                                        if (assemblyPrimaryButton != null) {
                                            com.quizlet.explanations.databinding.j jVar = new com.quizlet.explanations.databinding.j((ConstraintLayout) viewInflate, assemblySecondaryButton, radioGroup, assemblyInputLayout, assemblyPrimaryButton);
                                            Intrinsics.checkNotNullExpressionValue(jVar, "inflate(...)");
                                            return jVar;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putInt("CHECKED_OPTION_ID", ((com.quizlet.explanations.databinding.j) J()).c.getCheckedRadioButtonId());
        EditText editText = ((com.quizlet.explanations.databinding.j) J()).d.getEditText();
        outState.putString("OTHER_EXPLANATION", String.valueOf(editText != null ? editText.getText() : null));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        EditText editText;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        Integer numValueOf = bundle != null ? Integer.valueOf(bundle.getInt("CHECKED_OPTION_ID")) : null;
        String string = bundle != null ? bundle.getString("OTHER_EXPLANATION") : null;
        if (numValueOf != null) {
            ((com.quizlet.explanations.databinding.j) J()).c.check(numValueOf.intValue());
            AssemblyInputLayout otherEditText = ((com.quizlet.explanations.databinding.j) J()).d;
            Intrinsics.checkNotNullExpressionValue(otherEditText, "otherEditText");
            otherEditText.setVisibility(numValueOf.intValue() != R.id.reportOptionOther ? 4 : 0);
        }
        if (string != null && string.length() != 0 && (editText = ((com.quizlet.explanations.databinding.j) J()).d.getEditText()) != null) {
            editText.setText(string);
        }
        ((com.quizlet.explanations.databinding.j) J()).c.setOnCheckedChangeListener(new f(this, 0));
        EditText editText2 = ((com.quizlet.explanations.databinding.j) J()).d.getEditText();
        if (editText2 != null) {
            editText2.addTextChangedListener(new U0(this, 2));
        }
        final int i = 0;
        ((com.quizlet.explanations.databinding.j) J()).e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.explanations.feedback.ui.fragments.g
            public final /* synthetic */ ReportThisContentFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) throws Resources.NotFoundException {
                X6 feedback;
                String string2;
                Editable text;
                boolean z;
                ReportThisContentFragment reportThisContentFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ReportThisContentFragment.k;
                        int checkedRadioButtonId = ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).c.getCheckedRadioButtonId();
                        com.quizlet.explanations.feedback.data.d dVar = com.quizlet.explanations.feedback.data.d.c;
                        com.quizlet.explanations.feedback.data.d dVar2 = com.quizlet.explanations.feedback.data.d.b;
                        if (checkedRadioButtonId == R.id.reportOptionOne) {
                            feedback = dVar2;
                        } else if (checkedRadioButtonId == R.id.reportOptionTwo) {
                            feedback = dVar;
                        } else {
                            EditText editText3 = ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).d.getEditText();
                            if (editText3 == null || (text = editText3.getText()) == null || (string2 = text.toString()) == null) {
                                string2 = "";
                            }
                            feedback = new com.quizlet.explanations.feedback.data.e(string2);
                        }
                        if (feedback instanceof com.quizlet.explanations.feedback.data.e) {
                            boolean zO = StringsKt.O(((com.quizlet.explanations.feedback.data.e) feedback).a);
                            z = !zO;
                            ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).d.setError(zO ? reportThisContentFragment.getResources().getString(R.string.report_explanation_other_input_error) : null);
                        } else {
                            if (!feedback.equals(dVar2) && !feedback.equals(dVar)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            z = true;
                        }
                        if (z) {
                            int i2 = Resources.getSystem().getDisplayMetrics().widthPixels;
                            int i3 = Resources.getSystem().getDisplayMetrics().heightPixels;
                            com.quizlet.explanations.feedback.viewmodel.a aVar = (com.quizlet.explanations.feedback.viewmodel.a) reportThisContentFragment.j.getValue();
                            aVar.getClass();
                            Intrinsics.checkNotNullParameter(feedback, "feedback");
                            ExplanationsFeedbackSetUpState explanationsFeedbackSetUpState = aVar.h;
                            if (explanationsFeedbackSetUpState == null) {
                                aVar.g.j(Unit.a);
                                return;
                            }
                            W feedback2 = new W(explanationsFeedbackSetUpState.a(), i2, feedback.b(), i3);
                            com.quizlet.data.repository.activitycenter.b bVar = aVar.d;
                            bVar.getClass();
                            Intrinsics.checkNotNullParameter(feedback2, "feedback");
                            r stopToken = aVar.c;
                            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                            B7.c(((androidx.work.impl.model.c) bVar.c).a(stopToken, new com.braze.triggers.managers.h(21, bVar, feedback2)), null, new com.quizlet.data.repository.explanations.exercise.a(6, aVar, explanationsFeedbackSetUpState), 1);
                            return;
                        }
                        return;
                    default:
                        String str2 = ReportThisContentFragment.k;
                        ((com.quizlet.explanations.feedback.viewmodel.a) reportThisContentFragment.j.getValue()).g.j(Unit.a);
                        return;
                }
            }
        });
        final int i2 = 1;
        ((com.quizlet.explanations.databinding.j) J()).b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.explanations.feedback.ui.fragments.g
            public final /* synthetic */ ReportThisContentFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) throws Resources.NotFoundException {
                X6 feedback;
                String string2;
                Editable text;
                boolean z;
                ReportThisContentFragment reportThisContentFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ReportThisContentFragment.k;
                        int checkedRadioButtonId = ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).c.getCheckedRadioButtonId();
                        com.quizlet.explanations.feedback.data.d dVar = com.quizlet.explanations.feedback.data.d.c;
                        com.quizlet.explanations.feedback.data.d dVar2 = com.quizlet.explanations.feedback.data.d.b;
                        if (checkedRadioButtonId == R.id.reportOptionOne) {
                            feedback = dVar2;
                        } else if (checkedRadioButtonId == R.id.reportOptionTwo) {
                            feedback = dVar;
                        } else {
                            EditText editText3 = ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).d.getEditText();
                            if (editText3 == null || (text = editText3.getText()) == null || (string2 = text.toString()) == null) {
                                string2 = "";
                            }
                            feedback = new com.quizlet.explanations.feedback.data.e(string2);
                        }
                        if (feedback instanceof com.quizlet.explanations.feedback.data.e) {
                            boolean zO = StringsKt.O(((com.quizlet.explanations.feedback.data.e) feedback).a);
                            z = !zO;
                            ((com.quizlet.explanations.databinding.j) reportThisContentFragment.J()).d.setError(zO ? reportThisContentFragment.getResources().getString(R.string.report_explanation_other_input_error) : null);
                        } else {
                            if (!feedback.equals(dVar2) && !feedback.equals(dVar)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            z = true;
                        }
                        if (z) {
                            int i22 = Resources.getSystem().getDisplayMetrics().widthPixels;
                            int i3 = Resources.getSystem().getDisplayMetrics().heightPixels;
                            com.quizlet.explanations.feedback.viewmodel.a aVar = (com.quizlet.explanations.feedback.viewmodel.a) reportThisContentFragment.j.getValue();
                            aVar.getClass();
                            Intrinsics.checkNotNullParameter(feedback, "feedback");
                            ExplanationsFeedbackSetUpState explanationsFeedbackSetUpState = aVar.h;
                            if (explanationsFeedbackSetUpState == null) {
                                aVar.g.j(Unit.a);
                                return;
                            }
                            W feedback2 = new W(explanationsFeedbackSetUpState.a(), i22, feedback.b(), i3);
                            com.quizlet.data.repository.activitycenter.b bVar = aVar.d;
                            bVar.getClass();
                            Intrinsics.checkNotNullParameter(feedback2, "feedback");
                            r stopToken = aVar.c;
                            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                            B7.c(((androidx.work.impl.model.c) bVar.c).a(stopToken, new com.braze.triggers.managers.h(21, bVar, feedback2)), null, new com.quizlet.data.repository.explanations.exercise.a(6, aVar, explanationsFeedbackSetUpState), 1);
                            return;
                        }
                        return;
                    default:
                        String str2 = ReportThisContentFragment.k;
                        ((com.quizlet.explanations.feedback.viewmodel.a) reportThisContentFragment.j.getValue()).g.j(Unit.a);
                        return;
                }
            }
        });
    }
}

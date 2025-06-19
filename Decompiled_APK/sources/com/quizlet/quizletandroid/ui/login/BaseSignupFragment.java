package com.quizlet.quizletandroid.ui.login;

import android.content.Context;
import android.os.Bundle;
import android.text.SpannedString;
import android.text.method.LinkMovementMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.work.P;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QCheckBox;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.G;
import com.quizlet.quizletandroid.ui.common.views.DatePickerDialogFragment;
import com.quizlet.quizletandroid.ui.common.widgets.EditTextDatePicker;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public abstract class BaseSignupFragment extends BaseFragment<G> {
    public com.quizlet.quizletandroid.managers.g e;
    public io.reactivex.rxjava3.core.o f;
    public androidx.work.impl.model.v g;
    public androidx.work.impl.model.l h;
    public com.quizlet.time.b i;
    public com.quizlet.qutils.string.c j;
    public com.quizlet.uicommon.util.tooltip.a k;
    public io.reactivex.rxjava3.subjects.r l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e m = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.oldlogin.o.class), new e(this, 0), new e(this, 2), new e(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e n;
    public final kotlin.u o;
    public final com.quizlet.login.common.interactors.d p;

    public BaseSignupFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new e(this, 3), 10));
        this.n = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.login.viewmodels.j.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 11), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 3), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 12));
        this.o = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 17));
        this.p = new com.quizlet.login.common.interactors.d(this, 5);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_signup, viewGroup, false);
        int i = R.id.signup_dateofbirth_edittext;
        EditTextDatePicker editTextDatePicker = (EditTextDatePicker) AbstractC3375o2.c(R.id.signup_dateofbirth_edittext, viewInflate);
        if (editTextDatePicker != null) {
            i = R.id.signup_email_address_edittext;
            QFormField qFormField = (QFormField) AbstractC3375o2.c(R.id.signup_email_address_edittext, viewInflate);
            if (qFormField != null) {
                LinearLayout linearLayout = (LinearLayout) viewInflate;
                i = R.id.signup_form_child;
                if (((LinearLayout) AbstractC3375o2.c(R.id.signup_form_child, viewInflate)) != null) {
                    i = R.id.signup_form_label;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.signup_form_label, viewInflate);
                    if (qTextView != null) {
                        i = R.id.signup_legal_information_textview;
                        QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.signup_legal_information_textview, viewInflate);
                        if (qTextView2 != null) {
                            i = R.id.signup_password_edittext;
                            QFormField qFormField2 = (QFormField) AbstractC3375o2.c(R.id.signup_password_edittext, viewInflate);
                            if (qFormField2 != null) {
                                i = R.id.signup_show_password_checkbox;
                                if (((QCheckBox) AbstractC3375o2.c(R.id.signup_show_password_checkbox, viewInflate)) != null) {
                                    i = R.id.signup_signup_button;
                                    QButton qButton = (QButton) AbstractC3375o2.c(R.id.signup_signup_button, viewInflate);
                                    if (qButton != null) {
                                        i = R.id.signup_teacher;
                                        View viewC = AbstractC3375o2.c(R.id.signup_teacher, viewInflate);
                                        if (viewC != null) {
                                            int i2 = R.id.teacher_no;
                                            if (((QRadioButton) AbstractC3375o2.c(R.id.teacher_no, viewC)) != null) {
                                                i2 = R.id.teacher_yes;
                                                QRadioButton qRadioButton = (QRadioButton) AbstractC3375o2.c(R.id.teacher_yes, viewC);
                                                if (qRadioButton != null) {
                                                    G g = new G(linearLayout, editTextDatePicker, qFormField, qTextView, qTextView2, qFormField2, qButton, new com.quizlet.assembly.databinding.b(1, qRadioButton, (LinearLayout) viewC));
                                                    Intrinsics.checkNotNullExpressionValue(g, "inflate(...)");
                                                    return g;
                                                }
                                            }
                                            throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
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

    public final EditTextDatePicker Q() {
        EditTextDatePicker signupDateofbirthEdittext = ((G) J()).b;
        Intrinsics.checkNotNullExpressionValue(signupDateofbirthEdittext, "signupDateofbirthEdittext");
        return signupDateofbirthEdittext;
    }

    public final QFormField R() {
        QFormField signupEmailAddressEdittext = ((G) J()).c;
        Intrinsics.checkNotNullExpressionValue(signupEmailAddressEdittext, "signupEmailAddressEdittext");
        return signupEmailAddressEdittext;
    }

    public List S() {
        return kotlin.collections.B.j(Q(), ((G) J()).f, R());
    }

    public final com.quizlet.assembly.databinding.b T() {
        com.quizlet.assembly.databinding.b signupTeacher = ((G) J()).h;
        Intrinsics.checkNotNullExpressionValue(signupTeacher, "signupTeacher");
        return signupTeacher;
    }

    public final QButton U() {
        QButton signupSignupButton = ((G) J()).g;
        Intrinsics.checkNotNullExpressionValue(signupSignupButton, "signupSignupButton");
        return signupSignupButton;
    }

    public void V(Context context, final int i, final com.quizlet.time.c month, final int i2, final QFormField emailView, LinearLayout teacherOrStudentView) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(month, "month");
        Intrinsics.checkNotNullParameter(emailView, "emailView");
        Intrinsics.checkNotNullParameter(teacherOrStudentView, "teacherOrStudentView");
        androidx.work.impl.model.l lVar = this.h;
        if (lVar == null) {
            Intrinsics.m("signUpRequestParentEmailFeature");
            throw null;
        }
        I(B7.b(lVar.r(), io.reactivex.rxjava3.kotlin.c.b, new Function1() { // from class: com.quizlet.quizletandroid.ui.login.a
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                BaseSignupFragment baseSignupFragment = this.a;
                com.quizlet.quizletandroid.managers.g gVar = baseSignupFragment.e;
                if (gVar == null) {
                    Intrinsics.m("coppaComplianceMonitor");
                    throw null;
                }
                boolean zE = P.e(i, month, i2, gVar.b());
                QFormField qFormField = emailView;
                if (zBooleanValue || zE) {
                    qFormField.setLabel(baseSignupFragment.requireContext().getString(R.string.email_address_label));
                } else {
                    qFormField.setLabel(baseSignupFragment.requireContext().getString(R.string.parent_email_label));
                }
                return Unit.a;
            }
        }));
        if (P.e(i, month, i2, 22)) {
            if (teacherOrStudentView.getVisibility() != 0) {
                teacherOrStudentView.startAnimation(new com.quizlet.quizletandroid.ui.common.animations.a(teacherOrStudentView, 2));
            }
        } else if (teacherOrStudentView.getVisibility() != 8) {
            teacherOrStudentView.startAnimation(new com.quizlet.quizletandroid.ui.common.animations.a(teacherOrStudentView, 1));
        }
    }

    public final boolean W() {
        CharSequence text = Q().getText();
        if (text == null || text.length() != 0) {
            LocalDate localDateOf = LocalDate.of(Q().getYear(), Q().getMonth().a + 1, Q().getDay());
            if (this.i == null) {
                Intrinsics.m("timeProvider");
                throw null;
            }
            LocalDate localDateNow = LocalDate.now();
            Intrinsics.checkNotNullExpressionValue(localDateNow, "now(...)");
            if (localDateOf.isBefore(localDateNow)) {
                Q().setError(null);
                EditTextDatePicker editTextDatePickerQ = Q();
                editTextDatePickerQ.t = 0;
                editTextDatePickerQ.r = false;
                editTextDatePickerQ.k(false);
                editTextDatePickerQ.i();
                return true;
            }
        }
        Q().setError(getString(R.string.signup_birthdate_error));
        Q().getEditText().callOnClick();
        return false;
    }

    public boolean X() {
        String strValueOf = String.valueOf(R().getText());
        if (this.j == null) {
            Intrinsics.m("emailUtil");
            throw null;
        }
        if (com.quizlet.qutils.string.c.c(strValueOf)) {
            return true;
        }
        String string = getString(R.string.invalid_email);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        R().setError(string);
        R().requestFocus();
        return false;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        int day = Q().getDay();
        com.quizlet.time.c month = Q().getMonth();
        Intrinsics.checkNotNullExpressionValue(month, "getMonth(...)");
        int year = Q().getYear();
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        QFormField qFormFieldR = R();
        LinearLayout linearLayout = (LinearLayout) T().b;
        Intrinsics.checkNotNullExpressionValue(linearLayout, "getRoot(...)");
        V(contextRequireContext, year, month, day, qFormFieldR, linearLayout);
        io.reactivex.rxjava3.subjects.r rVarF = Z.f("create(...)");
        this.l = rVarF;
        EditText textChanges = R().getEditText();
        Intrinsics.f(textChanges, "$this$textChanges");
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new com.jakewharton.rxbinding4.widget.c(textChanges), 0);
        f fVar = new f(this, 0);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.internal.operators.observable.B b = new io.reactivex.rxjava3.internal.operators.observable.B(aVar, fVar, gVar, bVar, bVar);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        io.reactivex.rxjava3.core.o oVar = this.f;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        io.reactivex.rxjava3.disposables.b bVarU = new io.reactivex.rxjava3.internal.operators.observable.B(b.h(500L, timeUnit, oVar).q(g.b), new f(this, 1), gVar, bVar, bVar).l(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(this, 1)).m(new androidx.work.impl.model.v(27, this, rVarF), SubsamplingScaleImageView.TILE_SIZE_AUTO).u(new f(this, 2), new com.quizlet.billing.manager.d(timber.log.c.a, 9), bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        I(bVarU);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        io.reactivex.rxjava3.subjects.r rVar = this.l;
        if (rVar != null) {
            rVar.onSuccess(Unit.a);
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new C4684d(this, null), 3);
        G g = (G) J();
        g.f.getEditText().setTransformationMethod(new PasswordTransformationMethod());
        ((LinearLayout) T().b).setVisibility(8);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        SpannedString spannedStringC = androidx.camera.core.impl.utils.e.c(contextRequireContext, R.attr.textColorAccent, null);
        QTextView qTextView = g.e;
        qTextView.setText(spannedStringC);
        qTextView.setMovementMethod(LinkMovementMethod.getInstance());
        g.d.requestFocus();
        Q().setFormFieldIcon(this.p);
        Q().setOnDateSetListener(new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 9));
        Q().setShowDatePickerListener((com.quizlet.quizletandroid.ui.login.viewmodels.j) this.n.getValue());
        Fragment fragmentE = getParentFragmentManager().E("DatePickerDialogFragment");
        DatePickerDialogFragment datePickerDialogFragment = fragmentE instanceof DatePickerDialogFragment ? (DatePickerDialogFragment) fragmentE : null;
        if (datePickerDialogFragment != null) {
            datePickerDialogFragment.s = Q();
            datePickerDialogFragment.q = Q();
        }
        R().c(new com.google.android.material.textfield.a(this, 3));
    }
}

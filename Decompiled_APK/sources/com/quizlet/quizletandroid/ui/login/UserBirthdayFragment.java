package com.quizlet.quizletandroid.ui.login;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import androidx.work.P;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.G;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class UserBirthdayFragment extends Hilt_UserBirthdayFragment {
    public static final String w;
    public com.quizlet.data.repository.user.a v;

    static {
        Intrinsics.checkNotNullExpressionValue("UserBirthdayFragment", "getSimpleName(...)");
        w = "UserBirthdayFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return w;
    }

    @Override // com.quizlet.quizletandroid.ui.login.BaseSignupFragment
    public final List S() {
        return kotlin.collections.B.j(Q(), R());
    }

    @Override // com.quizlet.quizletandroid.ui.login.BaseSignupFragment
    public final void V(Context context, final int i, final com.quizlet.time.c month, final int i2, QFormField emailView, LinearLayout teacherOrStudentView) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(month, "month");
        Intrinsics.checkNotNullParameter(emailView, "emailView");
        Intrinsics.checkNotNullParameter(teacherOrStudentView, "teacherOrStudentView");
        super.V(context, i, month, i2, emailView, teacherOrStudentView);
        androidx.work.impl.model.l lVar = this.h;
        if (lVar == null) {
            Intrinsics.m("signUpRequestParentEmailFeature");
            throw null;
        }
        I(B7.b(lVar.r(), io.reactivex.rxjava3.kotlin.c.b, new Function1() { // from class: com.quizlet.quizletandroid.ui.login.C
            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                String str = UserBirthdayFragment.w;
                UserBirthdayFragment userBirthdayFragment = this.a;
                com.quizlet.quizletandroid.managers.g gVar = userBirthdayFragment.e;
                if (gVar == null) {
                    Intrinsics.m("coppaComplianceMonitor");
                    throw null;
                }
                userBirthdayFragment.R().setVisibility((zBooleanValue || P.e(i, month, i2, gVar.b())) ? 8 : 0);
                return Unit.a;
            }
        }));
        QButton qButtonU = U();
        CharSequence text = Q().getText();
        boolean z = false;
        if (text != null && text.length() > 0) {
            z = true;
        }
        qButtonU.setEnabled(z);
    }

    @Override // com.quizlet.quizletandroid.ui.login.BaseSignupFragment
    public final boolean X() {
        com.quizlet.quizletandroid.managers.g gVar = this.e;
        if (gVar != null) {
            return P.e(Q().getYear(), Q().getMonth(), Q().getDay(), gVar.b()) || super.X();
        }
        Intrinsics.m("coppaComplianceMonitor");
        throw null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        com.quizlet.data.repository.user.a aVar = this.v;
        if (aVar == null) {
            Intrinsics.m("gaLogger");
            throw null;
        }
        Intrinsics.checkNotNullExpressionValue("UserBirthdayFragment", "getSimpleName(...)");
        aVar.t("UserBirthdayFragment");
    }

    @Override // com.quizlet.quizletandroid.ui.login.BaseSignupFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        QFormField signupPasswordEdittext = ((G) J()).f;
        Intrinsics.checkNotNullExpressionValue(signupPasswordEdittext, "signupPasswordEdittext");
        signupPasswordEdittext.setVisibility(8);
        R().setVisibility(8);
        QTextView signupFormLabel = ((G) J()).d;
        Intrinsics.checkNotNullExpressionValue(signupFormLabel, "signupFormLabel");
        signupFormLabel.setText(getString(R.string.signup_final_details));
        U().setText(getString(R.string.create_account));
        U().setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 11));
    }
}

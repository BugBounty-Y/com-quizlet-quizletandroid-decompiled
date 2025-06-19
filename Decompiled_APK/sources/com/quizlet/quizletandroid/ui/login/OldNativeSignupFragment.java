package com.quizlet.quizletandroid.ui.login;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.navigation.compose.C1279l;
import androidx.work.P;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.G;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class OldNativeSignupFragment extends Hilt_OldNativeSignupFragment {
    public static final String x;
    public com.features.flashcards.creatormarketing.h v;
    public com.quizlet.data.connectivity.a w;

    static {
        Intrinsics.checkNotNullExpressionValue("OldNativeSignupFragment", "getSimpleName(...)");
        x = "OldNativeSignupFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return x;
    }

    public final void c0() {
        com.bumptech.glide.c.C(U(), false);
        for (QFormField qFormField : S()) {
            qFormField.t = 0;
            qFormField.r = false;
            qFormField.k(false);
            qFormField.i();
        }
        if (W() && X()) {
            com.quizlet.data.connectivity.a aVar = this.w;
            if (aVar == null) {
                Intrinsics.m("networkConnectivityManager");
                throw null;
            }
            if (!((com.quizlet.remote.connectivity.b) aVar).a().a) {
                e.a aVar2 = new e.a(requireContext());
                aVar2.f(R.string.unable_to_reach_quizlet_title);
                aVar2.c(R.string.unable_to_reach_quizlet_msg);
                aVar2.i = aVar2.a.getString(R.string.OK);
                aVar2.j = null;
                aVar2.b = false;
                aVar2.g();
                return;
            }
            com.features.flashcards.creatormarketing.h hVar = this.v;
            if (hVar == null) {
                Intrinsics.m("signUpLoginEventLogger");
                throw null;
            }
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.config.features.properties.d(29));
            int year = Q().getYear();
            com.quizlet.time.c month = Q().getMonth();
            int day = Q().getDay();
            QFormField signupPasswordEdittext = ((G) J()).f;
            Intrinsics.checkNotNullExpressionValue(signupPasswordEdittext, "signupPasswordEdittext");
            String password = String.valueOf(signupPasswordEdittext.getText());
            String email = String.valueOf(R().getText());
            QRadioButton teacherYes = (QRadioButton) T().c;
            Intrinsics.checkNotNullExpressionValue(teacherYes, "teacherYes");
            int i = P.e(year, month, day, 22) ? teacherYes.isChecked() ? 1 : 2 : 0;
            com.quizlet.login.oldlogin.o oVar = (com.quizlet.login.oldlogin.o) this.m.getValue();
            int i2 = month.a;
            int i3 = i2 + 1;
            com.quizlet.time.a birthMonth = new com.quizlet.time.a(i3);
            oVar.getClass();
            Intrinsics.checkNotNullParameter(password, "password");
            Intrinsics.checkNotNullParameter(birthMonth, "birthMonth");
            Intrinsics.checkNotNullParameter(email, "email");
            LinkedHashMap linkedHashMapG = V.g(new Pair("password1", password), new Pair("password2", password), new Pair("birthYear", String.valueOf(year)), new Pair("birthMonth", String.valueOf(i3)), new Pair("birthDay", String.valueOf(day)), new Pair("email", email), new Pair("isFreeTeacher", String.valueOf(i)), new Pair("state", UUID.randomUUID().toString()));
            int iB = ((com.quizlet.quizletandroid.managers.g) oVar.i).b();
            GregorianCalendar gregorianCalendar = new GregorianCalendar();
            GregorianCalendar gregorianCalendar2 = new GregorianCalendar(year + iB, i2, day);
            io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(oVar.h.r(), io.reactivex.rxjava3.kotlin.c.b, new C1279l(!(gregorianCalendar2.before(gregorianCalendar) || gregorianCalendar2.equals(gregorianCalendar)), linkedHashMapG, oVar, 4));
            Intrinsics.checkNotNullParameter(eVarB, "<this>");
            oVar.A(eVarB);
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        requireActivity().getWindow().setFlags(8192, 8192);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        R().getEditText().setOnEditorActionListener(new com.quizlet.login.recovery.forgotpassword.ui.b(this, 3));
        QFormField signupPasswordEdittext = ((G) J()).f;
        Intrinsics.checkNotNullExpressionValue(signupPasswordEdittext, "signupPasswordEdittext");
        androidx.camera.camera2.internal.compat.workaround.e eVar = new androidx.camera.camera2.internal.compat.workaround.e(15, false);
        eVar.b = false;
        signupPasswordEdittext.setFormFieldIcon(eVar);
        return viewOnCreateView;
    }

    @Override // com.quizlet.quizletandroid.ui.login.BaseSignupFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        U().setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 8));
    }
}

package com.quizlet.login.recovery.forgotpassword.ui;

import android.app.Dialog;
import android.os.Bundle;
import android.widget.EditText;
import androidx.lifecycle.p0;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class ForgotPasswordDialogFragment extends Hilt_ForgotPasswordDialogFragment {
    public static final String C;
    public com.quizlet.login.common.util.a A;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e B;

    static {
        Intrinsics.checkNotNullExpressionValue("ForgotPasswordDialogFragment", "getSimpleName(...)");
        C = "ForgotPasswordDialogFragment";
    }

    public ForgotPasswordDialogFragment() {
        k kVarA = l.a(m.c, new e(new assistantMode.experiments.a(this, 29), 0));
        this.B = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.recovery.forgotpassword.viewmodel.e.class), new f(kVarA, 0), new androidx.credentials.playservices.controllers.BeginSignIn.d(28, this, kVarA), new f(kVarA, 1));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        e.a aVar = new e.a(getContext());
        aVar.f(R.string.forgot_password_dialog_title);
        aVar.c(R.string.forgot_password_dialog_message);
        aVar.a(new com.quizlet.uicommon.ui.common.dialogs.d(aVar.a.getString(R.string.forgot_password_dialog_placeholder), 1), null);
        final int i = 0;
        aVar.e(R.string.OK, new com.quizlet.uicommon.ui.common.dialogs.f(this) { // from class: com.quizlet.login.recovery.forgotpassword.ui.a
            public final /* synthetic */ ForgotPasswordDialogFragment b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i2) {
                ForgotPasswordDialogFragment forgotPasswordDialogFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ForgotPasswordDialogFragment.C;
                        forgotPasswordDialogFragment.S();
                        break;
                    default:
                        String str2 = ForgotPasswordDialogFragment.C;
                        com.quizlet.login.recovery.forgotpassword.viewmodel.e eVar2 = (com.quizlet.login.recovery.forgotpassword.viewmodel.e) forgotPasswordDialogFragment.B.getValue();
                        eVar2.getClass();
                        E.A(p0.j(eVar2), null, null, new com.quizlet.login.recovery.forgotpassword.viewmodel.b(eVar2, null), 3);
                        break;
                }
            }
        });
        final int i2 = 1;
        aVar.d(R.string.cancel_dialog_button, new com.quizlet.uicommon.ui.common.dialogs.f(this) { // from class: com.quizlet.login.recovery.forgotpassword.ui.a
            public final /* synthetic */ ForgotPasswordDialogFragment b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i22) {
                ForgotPasswordDialogFragment forgotPasswordDialogFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ForgotPasswordDialogFragment.C;
                        forgotPasswordDialogFragment.S();
                        break;
                    default:
                        String str2 = ForgotPasswordDialogFragment.C;
                        com.quizlet.login.recovery.forgotpassword.viewmodel.e eVar2 = (com.quizlet.login.recovery.forgotpassword.viewmodel.e) forgotPasswordDialogFragment.B.getValue();
                        eVar2.getClass();
                        E.A(p0.j(eVar2), null, null, new com.quizlet.login.recovery.forgotpassword.viewmodel.b(eVar2, null), 3);
                        break;
                }
            }
        });
        aVar.b = true;
        com.quizlet.uicommon.ui.common.dialogs.e eVarB = aVar.b();
        Intrinsics.checkNotNullExpressionValue(eVarB, "create(...)");
        return eVarB;
    }

    public final void S() {
        final com.quizlet.login.recovery.forgotpassword.viewmodel.e eVar = (com.quizlet.login.recovery.forgotpassword.viewmodel.e) this.B.getValue();
        String input = ((com.quizlet.uicommon.ui.common.dialogs.e) L()).f(0).getText().toString();
        eVar.getClass();
        Intrinsics.checkNotNullParameter(input, "input");
        final int i = 0;
        final int i2 = 1;
        io.reactivex.rxjava3.internal.observers.e eVarI = eVar.c.w(input).l(eVar.d).h(eVar.e).i(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.login.recovery.forgotpassword.viewmodel.a
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i) {
                    case 0:
                        retrofit2.K p0 = (retrofit2.K) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        e eVar2 = eVar;
                        E.A(p0.j(eVar2), null, null, new d(eVar2, p0, null), 3);
                        break;
                    default:
                        Throwable p02 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        e eVar3 = eVar;
                        E.A(p0.j(eVar3), null, null, new c(eVar3, p02, null), 3);
                        break;
                }
            }
        }, new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.login.recovery.forgotpassword.viewmodel.a
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i2) {
                    case 0:
                        retrofit2.K p0 = (retrofit2.K) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        e eVar2 = eVar;
                        E.A(p0.j(eVar2), null, null, new d(eVar2, p0, null), 3);
                        break;
                    default:
                        Throwable p02 = (Throwable) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        e eVar3 = eVar;
                        E.A(p0.j(eVar3), null, null, new c(eVar3, p02, null), 3);
                        break;
                }
            }
        });
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        eVar.A(eVarI);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        E.A(p0.h(this), null, null, new d(this, null), 3);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        EditText editTextF = ((com.quizlet.uicommon.ui.common.dialogs.e) L()).f(0);
        editTextF.setInputType(1);
        editTextF.setOnEditorActionListener(new b(this, 0));
    }
}

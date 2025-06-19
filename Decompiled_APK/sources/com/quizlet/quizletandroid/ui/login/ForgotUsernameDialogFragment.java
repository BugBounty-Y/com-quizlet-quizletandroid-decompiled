package com.quizlet.quizletandroid.ui.login;

import android.app.Dialog;
import android.os.Bundle;
import android.widget.EditText;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import retrofit2.K;

/* loaded from: classes3.dex */
public class ForgotUsernameDialogFragment extends Hilt_ForgotUsernameDialogFragment {
    public IQuizletApiClient A;
    public io.reactivex.rxjava3.core.o B;
    public io.reactivex.rxjava3.core.o C;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        e.a aVar = new e.a(super.getContext());
        aVar.f(R.string.forgot_username);
        aVar.a(new com.quizlet.uicommon.ui.common.dialogs.d(aVar.a.getString(R.string.enter_your_email), 1), null);
        final int i = 1;
        aVar.e(R.string.OK, new com.quizlet.uicommon.ui.common.dialogs.f(this) { // from class: com.quizlet.quizletandroid.ui.login.k
            public final /* synthetic */ ForgotUsernameDialogFragment b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i2) {
                switch (i) {
                    case 0:
                        this.b.H(false, false);
                        break;
                    default:
                        this.b.S();
                        break;
                }
            }
        });
        final int i2 = 0;
        aVar.d(R.string.cancel_dialog_button, new com.quizlet.uicommon.ui.common.dialogs.f(this) { // from class: com.quizlet.quizletandroid.ui.login.k
            public final /* synthetic */ ForgotUsernameDialogFragment b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i22) {
                switch (i2) {
                    case 0:
                        this.b.H(false, false);
                        break;
                    default:
                        this.b.S();
                        break;
                }
            }
        });
        aVar.b = true;
        return aVar.b();
    }

    public final void S() {
        final int i = 0;
        final int i2 = 1;
        this.A.s(((com.quizlet.uicommon.ui.common.dialogs.e) this.l).f(0).getText().toString()).l(this.B).h(this.C).i(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.login.l
            public final /* synthetic */ ForgotUsernameDialogFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i) {
                    case 0:
                        K k = (K) obj;
                        ForgotUsernameDialogFragment forgotUsernameDialogFragment = this.b;
                        if (forgotUsernameDialogFragment.isAdded() && com.quizlet.login.common.util.a.a(forgotUsernameDialogFragment.requireContext(), (ApiThreeWrapper) k.b, null, forgotUsernameDialogFragment.getString(R.string.check_email_username))) {
                            forgotUsernameDialogFragment.l.dismiss();
                            break;
                        }
                        break;
                    default:
                        Throwable th = (Throwable) obj;
                        ForgotUsernameDialogFragment forgotUsernameDialogFragment2 = this.b;
                        if (forgotUsernameDialogFragment2.isAdded() && com.quizlet.login.common.util.a.a(forgotUsernameDialogFragment2.requireContext(), null, th, forgotUsernameDialogFragment2.getString(R.string.check_email_username))) {
                            forgotUsernameDialogFragment2.l.dismiss();
                            break;
                        }
                        break;
                }
            }
        }, new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.login.l
            public final /* synthetic */ ForgotUsernameDialogFragment b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i2) {
                    case 0:
                        K k = (K) obj;
                        ForgotUsernameDialogFragment forgotUsernameDialogFragment = this.b;
                        if (forgotUsernameDialogFragment.isAdded() && com.quizlet.login.common.util.a.a(forgotUsernameDialogFragment.requireContext(), (ApiThreeWrapper) k.b, null, forgotUsernameDialogFragment.getString(R.string.check_email_username))) {
                            forgotUsernameDialogFragment.l.dismiss();
                            break;
                        }
                        break;
                    default:
                        Throwable th = (Throwable) obj;
                        ForgotUsernameDialogFragment forgotUsernameDialogFragment2 = this.b;
                        if (forgotUsernameDialogFragment2.isAdded() && com.quizlet.login.common.util.a.a(forgotUsernameDialogFragment2.requireContext(), null, th, forgotUsernameDialogFragment2.getString(R.string.check_email_username))) {
                            forgotUsernameDialogFragment2.l.dismiss();
                            break;
                        }
                        break;
                }
            }
        });
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        EditText editTextF = ((com.quizlet.uicommon.ui.common.dialogs.e) this.l).f(0);
        editTextF.setInputType(33);
        editTextF.setOnEditorActionListener(new com.quizlet.login.recovery.forgotpassword.ui.b(this, 2));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.z;
    }
}

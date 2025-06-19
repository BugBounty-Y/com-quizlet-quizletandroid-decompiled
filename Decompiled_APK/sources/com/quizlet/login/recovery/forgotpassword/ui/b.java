package com.quizlet.login.recovery.forgotpassword.ui;

import android.view.KeyEvent;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.quizlet.partskit.widgets.QEditText;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.ForgotUsernameDialogFragment;
import com.quizlet.quizletandroid.ui.login.OldNativeSignupFragment;
import com.quizlet.quizletandroid.ui.setcreation.activities.InputPasswordActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements TextView.OnEditorActionListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.widget.TextView.OnEditorActionListener
    public final boolean onEditorAction(TextView view, int i, KeyEvent keyEvent) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = ForgotPasswordDialogFragment.C;
                if (i != 2 && i != 6) {
                    return false;
                }
                ((ForgotPasswordDialogFragment) obj).S();
                return true;
            case 1:
                int i2 = QEditText.j;
                Intrinsics.checkNotNullParameter(view, "view");
                if (i != 6) {
                    return false;
                }
                QEditText qEditText = (QEditText) obj;
                if (qEditText.i.isFullscreenMode() && qEditText.g != null && qEditText.getHint() == null) {
                    qEditText.setHint((CharSequence) null);
                }
                qEditText.i.hideSoftInputFromWindow(view.getWindowToken(), 0);
                return true;
            case 2:
                ForgotUsernameDialogFragment forgotUsernameDialogFragment = (ForgotUsernameDialogFragment) obj;
                forgotUsernameDialogFragment.getClass();
                if (i != 2 && i != 6) {
                    return false;
                }
                forgotUsernameDialogFragment.S();
                return true;
            case 3:
                String str2 = OldNativeSignupFragment.x;
                Intrinsics.d(view);
                OldNativeSignupFragment oldNativeSignupFragment = (OldNativeSignupFragment) obj;
                if (i != 6) {
                    oldNativeSignupFragment.getClass();
                    if (keyEvent == null || keyEvent.getAction() != 1 || keyEvent.getKeyCode() != 66) {
                        return false;
                    }
                }
                LinearLayout linearLayout = (LinearLayout) oldNativeSignupFragment.T().b;
                Intrinsics.checkNotNullExpressionValue(linearLayout, "getRoot(...)");
                if (linearLayout.getVisibility() == 0) {
                    com.bumptech.glide.c.C(view, false);
                    return true;
                }
                oldNativeSignupFragment.c0();
                return true;
            case 4:
                String str3 = InputPasswordActivity.t;
                if (i == 6) {
                    return ((InputPasswordActivity) obj).c0();
                }
                return false;
            default:
                int i3 = WriteModePromptView.W;
                WriteModePromptView writeModePromptView = (WriteModePromptView) obj;
                writeModePromptView.getClass();
                if ((keyEvent != null && keyEvent.getAction() != 0) || (i != R.integer.learn_mode_submit_key_action && i != 0 && ((keyEvent == null || keyEvent.getKeyCode() != 66) && i != 6 && i != 2 && i != 5 && i != 4))) {
                    return false;
                }
                if (!writeModePromptView.G) {
                    writeModePromptView.h();
                    return true;
                }
                writeModePromptView.i();
                writeModePromptView.C.c(false);
                return true;
        }
    }
}

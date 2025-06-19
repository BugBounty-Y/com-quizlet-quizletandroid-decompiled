package com.facebook.login;

import android.app.Dialog;
import androidx.fragment.app.I;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class l extends Dialog {
    public final /* synthetic */ DeviceAuthDialog a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(DeviceAuthDialog deviceAuthDialog, I i) {
        super(i, R.style.com_facebook_auth_dialog);
        this.a = deviceAuthDialog;
    }

    @Override // android.app.Dialog
    public final void onBackPressed() {
        this.a.getClass();
        super.onBackPressed();
    }
}

package com.quizlet.quizletandroid.ui.login;

import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ BaseSignupFragment b;

    public /* synthetic */ f(BaseSignupFragment baseSignupFragment, int i) {
        this.a = i;
        this.b = baseSignupFragment;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                CharSequence it2 = (CharSequence) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                QFormField qFormFieldR = this.b.R();
                qFormFieldR.t = 0;
                qFormFieldR.r = false;
                qFormFieldR.k(false);
                qFormFieldR.i();
                break;
            case 1:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.U().setEnabled(false);
                break;
            default:
                com.quizlet.data.model.B p0 = (com.quizlet.data.model.B) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                BaseSignupFragment baseSignupFragment = this.b;
                if (!p0.b) {
                    if (!p0.a) {
                        baseSignupFragment.R().setError(baseSignupFragment.getString(R.string.invalid_email));
                        break;
                    } else {
                        baseSignupFragment.U().setEnabled(true);
                        baseSignupFragment.R().setSuccess(null);
                        break;
                    }
                } else {
                    baseSignupFragment.R().setError(baseSignupFragment.getString(R.string.account_with_email_already_exists));
                    break;
                }
        }
    }
}

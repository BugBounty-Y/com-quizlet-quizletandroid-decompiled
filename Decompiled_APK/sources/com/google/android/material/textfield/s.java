package com.google.android.material.textfield;

import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.EditText;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class s extends m {
    public final int e;
    public EditText f;
    public final com.braze.ui.inappmessage.d g;

    public s(l lVar, int i) {
        super(lVar);
        this.e = R.drawable.design_password_eye;
        this.g = new com.braze.ui.inappmessage.d(this, 7);
        if (i != 0) {
            this.e = i;
        }
    }

    @Override // com.google.android.material.textfield.m
    public final void b() {
        q();
    }

    @Override // com.google.android.material.textfield.m
    public final int c() {
        return R.string.password_toggle_content_description;
    }

    @Override // com.google.android.material.textfield.m
    public final int d() {
        return this.e;
    }

    @Override // com.google.android.material.textfield.m
    public final View.OnClickListener f() {
        return this.g;
    }

    @Override // com.google.android.material.textfield.m
    public final boolean k() {
        return true;
    }

    @Override // com.google.android.material.textfield.m
    public final boolean l() {
        EditText editText = this.f;
        return !(editText != null && (editText.getTransformationMethod() instanceof PasswordTransformationMethod));
    }

    @Override // com.google.android.material.textfield.m
    public final void m(EditText editText) {
        this.f = editText;
        q();
    }

    @Override // com.google.android.material.textfield.m
    public final void r() {
        EditText editText = this.f;
        if (editText != null) {
            if (editText.getInputType() == 16 || editText.getInputType() == 128 || editText.getInputType() == 144 || editText.getInputType() == 224) {
                this.f.setTransformationMethod(PasswordTransformationMethod.getInstance());
            }
        }
    }

    @Override // com.google.android.material.textfield.m
    public final void s() {
        EditText editText = this.f;
        if (editText != null) {
            editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
    }
}

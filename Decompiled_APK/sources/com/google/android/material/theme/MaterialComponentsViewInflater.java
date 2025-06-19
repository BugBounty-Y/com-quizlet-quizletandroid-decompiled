package com.google.android.material.theme;

import android.content.Context;
import android.util.AttributeSet;
import androidx.appcompat.app.G;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.C0103p;
import androidx.appcompat.widget.D;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.radiobutton.a;
import com.google.android.material.textfield.r;

/* loaded from: classes2.dex */
public class MaterialComponentsViewInflater extends G {
    @Override // androidx.appcompat.app.G
    public final C0103p a(Context context, AttributeSet attributeSet) {
        return new r(context, attributeSet);
    }

    @Override // androidx.appcompat.app.G
    public final AppCompatButton b(Context context, AttributeSet attributeSet) {
        return new MaterialButton(context, attributeSet);
    }

    @Override // androidx.appcompat.app.G
    public final androidx.appcompat.widget.r c(Context context, AttributeSet attributeSet) {
        return new MaterialCheckBox(context, attributeSet);
    }

    @Override // androidx.appcompat.app.G
    public final D d(Context context, AttributeSet attributeSet) {
        return new a(context, attributeSet, 0);
    }

    @Override // androidx.appcompat.app.G
    public final AppCompatTextView e(Context context, AttributeSet attributeSet) {
        return new com.google.android.material.textview.a(context, attributeSet);
    }
}

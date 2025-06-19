package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.CheckBox;
import android.widget.RadioButton;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class A extends F0 {
    public final CheckBox a;
    public final RadioButton b;

    public A(View view) {
        super(view);
        this.a = (CheckBox) view.findViewById(R.id.multi_selection);
        this.b = (RadioButton) view.findViewById(R.id.single_selection);
    }
}

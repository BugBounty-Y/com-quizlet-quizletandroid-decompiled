package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.CheckBox;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class n extends F0 {
    public final TextView a;
    public final CheckBox b;
    public final View c;

    public n(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.purpose_name);
        this.b = (CheckBox) view.findViewById(R.id.purpose_select);
        this.c = view.findViewById(R.id.purpose_name_divider);
    }
}

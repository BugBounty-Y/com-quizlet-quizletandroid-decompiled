package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class I extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final TextView d;

    public I(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.domain_label);
        this.b = (TextView) view.findViewById(R.id.domain_value);
        this.c = (TextView) view.findViewById(R.id.used_label);
        this.d = (TextView) view.findViewById(R.id.used_val);
    }
}

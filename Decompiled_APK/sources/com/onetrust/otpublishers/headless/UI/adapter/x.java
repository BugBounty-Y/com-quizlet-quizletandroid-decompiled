package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class x extends F0 {
    public final TextView a;
    public final TextView b;
    public final LinearLayout c;

    public x(View view) {
        super(view);
        this.b = (TextView) view.findViewById(R.id.item_title);
        this.a = (TextView) view.findViewById(R.id.item_status);
        this.c = (LinearLayout) view.findViewById(R.id.main_layout);
    }
}

package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class A extends F0 {
    public final TextView a;
    public final TextView b;
    public final LinearLayout c;

    public A(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.tv_grp_name);
        this.c = (LinearLayout) view.findViewById(R.id.tv_grp_layout);
        this.b = (TextView) view.findViewById(R.id.tv_group_vendor_count);
    }
}

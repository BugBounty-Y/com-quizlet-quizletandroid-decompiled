package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class q extends F0 {
    public final TextView a;
    public final LinearLayout b;

    public q(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.tv_grp_name);
        this.b = (LinearLayout) view.findViewById(R.id.tv_grp_layout);
    }
}

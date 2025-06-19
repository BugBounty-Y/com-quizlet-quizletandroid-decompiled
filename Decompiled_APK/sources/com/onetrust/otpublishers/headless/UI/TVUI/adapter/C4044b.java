package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* renamed from: com.onetrust.otpublishers.headless.UI.TVUI.adapter.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4044b extends F0 {
    public final TextView a;
    public final TextView b;
    public final LinearLayout c;

    public C4044b(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.tv_grp_name);
        this.c = (LinearLayout) view.findViewById(R.id.tv_grp_layout);
        this.b = (TextView) view.findViewById(R.id.tv_group_vendor_count);
    }
}

package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class k extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final TextView d;
    public final ImageView e;
    public final LinearLayout f;

    public k(View view) {
        super(view);
        this.b = (TextView) view.findViewById(R.id.tv_grp_name);
        this.c = (TextView) view.findViewById(R.id.tv_sub_group_vendor_count);
        this.d = (TextView) view.findViewById(R.id.always_active_textview);
        this.a = (TextView) view.findViewById(R.id.group_status_text);
        this.e = (ImageView) view.findViewById(R.id.group_show_more);
        this.f = (LinearLayout) view.findViewById(R.id.tv_grp_layout);
    }
}

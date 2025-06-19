package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class o extends F0 {
    public final TextView a;
    public final CheckBox b;
    public final LinearLayout c;
    public final CardView d;

    public o(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.ot_tv_filter_purpose);
        this.b = (CheckBox) view.findViewById(R.id.ot_tv_filter_item_cb);
        this.c = (LinearLayout) view.findViewById(R.id.ot_tv_filter_item_layout);
        this.d = (CardView) view.findViewById(R.id.ot_tv_filter_item_card);
    }
}

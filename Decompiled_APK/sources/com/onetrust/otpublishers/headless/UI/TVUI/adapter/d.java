package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class d extends F0 {
    public final TextView a;
    public final RelativeLayout b;
    public final View c;

    public d(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.iab_illustration_purpose_item);
        this.b = (RelativeLayout) view.findViewById(R.id.iab_illustration_item_header);
        this.c = view.findViewById(R.id.iab_illustration_purpose_item_divider);
    }
}

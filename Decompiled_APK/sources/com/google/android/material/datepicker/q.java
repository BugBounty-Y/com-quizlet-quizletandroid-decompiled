package com.google.android.material.datepicker;

import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.view.V;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class q extends F0 {
    public final TextView a;
    public final MaterialCalendarGridView b;

    public q(LinearLayout linearLayout, boolean z) {
        super(linearLayout);
        TextView textView = (TextView) linearLayout.findViewById(R.id.month_title);
        this.a = textView;
        V.p(textView, true);
        this.b = (MaterialCalendarGridView) linearLayout.findViewById(R.id.month_grid);
        if (z) {
            return;
        }
        textView.setVisibility(8);
    }
}

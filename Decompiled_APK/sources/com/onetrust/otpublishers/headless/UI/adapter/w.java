package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class w extends F0 {
    public final TextView a;
    public final TextView b;
    public final SwitchCompat c;
    public final RecyclerView d;
    public final RecyclerView e;
    public final View f;

    public w(View view) {
        super(view);
        this.b = (TextView) view.findViewById(R.id.purpose_name);
        this.a = (TextView) view.findViewById(R.id.purpose_description);
        this.e = (RecyclerView) view.findViewById(R.id.consent_preferences_list_child);
        this.d = (RecyclerView) view.findViewById(R.id.consent_preferences_list_topic);
        this.c = (SwitchCompat) view.findViewById(R.id.purpose_toggle);
        this.f = view.findViewById(R.id.purpose_divider);
    }
}

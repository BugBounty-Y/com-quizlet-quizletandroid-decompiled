package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4056l extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final SwitchCompat d;
    public final ImageView e;
    public final View f;

    public C4056l(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.group_name);
        this.b = (TextView) view.findViewById(R.id.group_vendor_count);
        this.d = (SwitchCompat) view.findViewById(R.id.consent_switch);
        this.c = (TextView) view.findViewById(R.id.alwaysActiveText);
        this.f = view.findViewById(R.id.view3);
        this.e = (ImageView) view.findViewById(R.id.show_more);
    }
}

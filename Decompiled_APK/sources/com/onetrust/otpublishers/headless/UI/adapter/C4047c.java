package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4047c extends F0 {
    public final TextView a;
    public final RelativeLayout b;
    public final View c;
    public final TextView d;
    public final TextView e;
    public final TextView f;

    public C4047c(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.iab_illustration_purpose_item);
        this.b = (RelativeLayout) view.findViewById(R.id.iab_illustration_item_header);
        this.c = view.findViewById(R.id.iab_illustration_purpose_item_divider);
        this.d = (TextView) view.findViewById(R.id.general_vendor_description);
        this.e = (TextView) view.findViewById(R.id.general_vendor_sdk_list_title);
        this.f = (TextView) view.findViewById(R.id.view_powered_by_logo);
    }
}

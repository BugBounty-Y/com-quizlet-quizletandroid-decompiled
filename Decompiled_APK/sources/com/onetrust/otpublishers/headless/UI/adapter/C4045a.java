package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4045a extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final TextView d;

    public C4045a(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.vd_purpose_item);
        this.b = (TextView) view.findViewById(R.id.general_vendor_description);
        this.c = (TextView) view.findViewById(R.id.general_vendor_sdk_list_title);
        this.d = (TextView) view.findViewById(R.id.view_powered_by_logo);
    }
}

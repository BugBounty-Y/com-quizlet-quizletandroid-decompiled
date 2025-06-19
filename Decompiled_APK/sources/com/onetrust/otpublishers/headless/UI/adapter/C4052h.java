package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4052h extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final TextView d;
    public final TextView e;
    public final TextView f;
    public final TextView g;
    public final TextView h;
    public final SwitchCompat i;
    public final SwitchCompat j;
    public final SwitchCompat k;
    public final View l;
    public final LinearLayout m;

    public C4052h(View view) {
        super(view);
        this.d = (TextView) view.findViewById(R.id.sub_group_name);
        this.e = (TextView) view.findViewById(R.id.pc_details_group_vendor_count);
        this.f = (TextView) view.findViewById(R.id.sub_group_desc);
        this.a = (TextView) view.findViewById(R.id.view_iab_illustration);
        this.i = (SwitchCompat) view.findViewById(R.id.consent_toggle);
        this.j = (SwitchCompat) view.findViewById(R.id.legitInt_toggle);
        this.b = (TextView) view.findViewById(R.id.tv_consent);
        this.c = (TextView) view.findViewById(R.id.tv_legit_Int);
        this.g = (TextView) view.findViewById(R.id.alwaysActiveTextChild);
        this.h = (TextView) view.findViewById(R.id.alwaysActiveText_non_iab);
        this.k = (SwitchCompat) view.findViewById(R.id.consent_toggle_non_iab);
        this.l = view.findViewById(R.id.item_divider);
        this.m = (LinearLayout) view.findViewById(R.id.group_name_layout);
    }
}

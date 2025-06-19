package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class w extends F0 {
    public final TextView a;
    public final TextView b;
    public final TextView c;
    public final TextView d;
    public final TextView e;
    public final TextView f;
    public final TextView g;
    public final TextView h;
    public final TextView i;
    public final RecyclerView j;
    public final LinearLayout k;
    public final LinearLayout l;
    public final LinearLayout m;
    public final LinearLayout n;
    public final LinearLayout o;

    public w(View view) {
        super(view);
        this.a = (TextView) view.findViewById(R.id.disclosure_id_label);
        this.b = (TextView) view.findViewById(R.id.disclosure_type_label);
        this.c = (TextView) view.findViewById(R.id.disclosure_ls_label);
        this.d = (TextView) view.findViewById(R.id.disclosure_domain_label);
        this.e = (TextView) view.findViewById(R.id.disclosure_purpose_label);
        this.f = (TextView) view.findViewById(R.id.disclosure_id_val);
        this.g = (TextView) view.findViewById(R.id.disclosure_type_val);
        this.h = (TextView) view.findViewById(R.id.disclosure_ls_val);
        this.i = (TextView) view.findViewById(R.id.disclosure_domain_val);
        this.j = (RecyclerView) view.findViewById(R.id.disclosure_purpose_listview);
        this.k = (LinearLayout) view.findViewById(R.id.disclosure_id_lyt);
        this.l = (LinearLayout) view.findViewById(R.id.disclosure_type_lyt);
        this.m = (LinearLayout) view.findViewById(R.id.disclosure_ls_lyt);
        this.n = (LinearLayout) view.findViewById(R.id.disclosure_domain_lyt);
        this.o = (LinearLayout) view.findViewById(R.id.disclosure_purpose_lyt);
    }
}

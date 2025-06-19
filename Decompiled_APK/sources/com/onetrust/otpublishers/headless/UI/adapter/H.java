package com.onetrust.otpublishers.headless.UI.adapter;

import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class H extends F0 {
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

    public H(View view) {
        super(view);
        this.b = (TextView) view.findViewById(R.id.disclosure_id_label);
        this.e = (TextView) view.findViewById(R.id.disclosure_type_label);
        this.c = (TextView) view.findViewById(R.id.disclosure_ls_label);
        this.d = (TextView) view.findViewById(R.id.disclosure_domain_label);
        this.a = (TextView) view.findViewById(R.id.disclosure_purpose_label);
        this.f = (TextView) view.findViewById(R.id.disclosure_id_val);
        this.g = (TextView) view.findViewById(R.id.disclosure_type_val);
        this.h = (TextView) view.findViewById(R.id.disclosure_ls_val);
        this.i = (TextView) view.findViewById(R.id.disclosure_domain_val);
        this.j = (RecyclerView) view.findViewById(R.id.disclosure_purpose_listview);
    }
}

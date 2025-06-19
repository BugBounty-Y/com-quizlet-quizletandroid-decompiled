package com.quizlet.features.infra.snackbar;

import android.content.res.Resources;
import android.view.View;
import android.widget.TextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class b {
    public final View a;
    public CharSequence b;
    public String c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public com.braze.ui.inappmessage.f j;

    public b(View view) {
        if (view == null) {
            throw new NullPointerException("view == null");
        }
        this.a = view;
    }

    public final com.google.android.material.snackbar.h a() throws Resources.NotFoundException {
        if (this.b == null) {
            this.b = "";
        }
        CharSequence charSequence = this.b;
        View view = this.a;
        com.google.android.material.snackbar.h hVarG = com.google.android.material.snackbar.h.g(view, charSequence);
        com.google.android.material.snackbar.f fVar = hVarG.i;
        TextView textView = (TextView) fVar.findViewById(R.id.snackbar_text);
        TextView textView2 = (TextView) fVar.findViewById(R.id.snackbar_action);
        if (this.g != 0) {
            float dimension = view.getContext().getResources().getDimension(this.g);
            textView.setTextSize(0, dimension);
            textView2.setTextSize(0, dimension);
        }
        int i = this.e;
        if (i != 0) {
            textView.setTextColor(i);
        }
        int i2 = this.f;
        if (i2 != 0) {
            textView2.setTextColor(i2);
        }
        int i3 = this.d;
        if (i3 != 0) {
            fVar.setBackgroundColor(i3);
        }
        int i4 = this.h;
        if (i4 != 0) {
            textView2.setBackgroundResource(i4);
        }
        int i5 = this.i;
        if (i5 != 0) {
            textView.setCompoundDrawablesWithIntrinsicBounds(i5, 0, 0, 0);
            textView.setCompoundDrawablePadding(fVar.getResources().getDimensionPixelOffset(R.dimen.snackbar_icon_padding));
        }
        textView.setGravity(16);
        textView.setTypeface(androidx.core.content.res.k.a(textView.getContext(), com.quizlet.ui.resources.designsystem.generated.a.d), 0);
        hVarG.h(this.c, this.j);
        return hVarG;
    }
}

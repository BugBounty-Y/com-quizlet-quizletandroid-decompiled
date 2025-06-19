package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RelativeLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QCheckBox;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class c implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final RelativeLayout b;
    public final QTextView c;
    public final FrameLayout d;
    public final FrameLayout e;
    public final RelativeLayout f;
    public final LinearLayout g;
    public final View h;
    public final QTextView i;
    public final LinearLayout j;
    public final QTextView k;
    public final QButton l;
    public final QButton m;
    public final QTextView n;

    public c(LinearLayout linearLayout, RelativeLayout relativeLayout, QCheckBox qCheckBox, QTextView qTextView, LinearLayout linearLayout2, FrameLayout frameLayout, FrameLayout frameLayout2, RelativeLayout relativeLayout2, LinearLayout linearLayout3, ListView listView, ImageView imageView, View view, QTextView qTextView2, RelativeLayout relativeLayout3, LinearLayout linearLayout4, QTextView qTextView3, QButton qButton, QButton qButton2, QTextView qTextView4) {
        this.a = linearLayout;
        this.b = relativeLayout;
        this.c = qTextView;
        this.d = frameLayout;
        this.e = frameLayout2;
        this.f = relativeLayout2;
        this.g = linearLayout3;
        this.h = view;
        this.i = qTextView2;
        this.j = linearLayout4;
        this.k = qTextView3;
        this.l = qButton;
        this.m = qButton2;
        this.n = qTextView4;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.upgrade.databinding;

import android.view.View;
import android.widget.TextView;

/* loaded from: classes3.dex */
public final class e implements androidx.viewbinding.a {
    public final TextView a;
    public final TextView b;

    public e(TextView textView, TextView textView2) {
        this.a = textView;
        this.b = textView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

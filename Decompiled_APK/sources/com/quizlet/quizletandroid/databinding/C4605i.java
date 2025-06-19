package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.quizlet.partskit.widgets.QTextView;

/* renamed from: com.quizlet.quizletandroid.databinding.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4605i implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final ImageView b;
    public final FrameLayout c;
    public final QTextView d;
    public final J e;

    public C4605i(FrameLayout frameLayout, ImageView imageView, FrameLayout frameLayout2, QTextView qTextView, J j) {
        this.a = frameLayout;
        this.b = imageView;
        this.c = frameLayout2;
        this.d = qTextView;
        this.e = j;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.IconFontTextView;

/* loaded from: classes3.dex */
public final class I implements androidx.viewbinding.a {
    public final /* synthetic */ int a = 0;
    public final ViewGroup b;

    public I(FrameLayout frameLayout) {
        this.b = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (FrameLayout) this.b;
            case 1:
                return (FrameLayout) this.b;
            default:
                return (LinearLayout) this.b;
        }
    }

    public I(FrameLayout frameLayout, IconFontTextView iconFontTextView) {
        this.b = frameLayout;
    }

    public I(LinearLayout linearLayout, QTextView qTextView, QTextView qTextView2) {
        this.b = linearLayout;
    }
}

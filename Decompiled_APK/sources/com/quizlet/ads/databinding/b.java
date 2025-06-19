package com.quizlet.ads.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.ads.nativead.NativeAdView;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class b implements androidx.viewbinding.a {
    public final NativeAdView a;
    public final QTextView b;
    public final AppCompatImageView c;
    public final QTextView d;
    public final QTextView e;
    public final AssemblySecondaryButton f;
    public final ConstraintLayout g;
    public final FrameLayout h;

    public b(NativeAdView nativeAdView, QTextView qTextView, AppCompatImageView appCompatImageView, QTextView qTextView2, QTextView qTextView3, AssemblySecondaryButton assemblySecondaryButton, ConstraintLayout constraintLayout, FrameLayout frameLayout) {
        this.a = nativeAdView;
        this.b = qTextView;
        this.c = appCompatImageView;
        this.d = qTextView2;
        this.e = qTextView3;
        this.f = assemblySecondaryButton;
        this.g = constraintLayout;
        this.h = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

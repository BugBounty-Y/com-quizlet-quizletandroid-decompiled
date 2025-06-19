package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ImageView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.SquareFrameLayout;

/* loaded from: classes3.dex */
public final class k0 implements androidx.viewbinding.a {
    public final SquareFrameLayout a;
    public final ImageView b;

    public k0(SquareFrameLayout squareFrameLayout, ImageView imageView) {
        this.a = squareFrameLayout;
        this.b = imageView;
    }

    public static k0 a(View view) {
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.image_view, view);
        if (imageView != null) {
            return new k0((SquareFrameLayout) view, imageView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.image_view)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}

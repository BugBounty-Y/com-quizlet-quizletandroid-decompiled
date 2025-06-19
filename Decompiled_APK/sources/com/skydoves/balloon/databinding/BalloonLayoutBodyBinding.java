package com.skydoves.balloon.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.skydoves.balloon.R;
import com.skydoves.balloon.radius.RadiusLayout;
import com.skydoves.balloon.vectortext.VectorTextView;

/* loaded from: classes3.dex */
public final class BalloonLayoutBodyBinding implements a {

    @NonNull
    public final FrameLayout balloon;

    @NonNull
    public final ImageView balloonArrow;

    @NonNull
    public final RadiusLayout balloonCard;

    @NonNull
    public final FrameLayout balloonContent;

    @NonNull
    public final VectorTextView balloonText;

    @NonNull
    public final FrameLayout balloonWrapper;

    @NonNull
    private final FrameLayout rootView;

    private BalloonLayoutBodyBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull ImageView imageView, @NonNull RadiusLayout radiusLayout, @NonNull FrameLayout frameLayout3, @NonNull VectorTextView vectorTextView, @NonNull FrameLayout frameLayout4) {
        this.rootView = frameLayout;
        this.balloon = frameLayout2;
        this.balloonArrow = imageView;
        this.balloonCard = radiusLayout;
        this.balloonContent = frameLayout3;
        this.balloonText = vectorTextView;
        this.balloonWrapper = frameLayout4;
    }

    @NonNull
    public static BalloonLayoutBodyBinding bind(@NonNull View view) {
        FrameLayout frameLayout = (FrameLayout) view;
        int i = R.id.balloon_arrow;
        ImageView imageView = (ImageView) AbstractC3375o2.c(i, view);
        if (imageView != null) {
            i = R.id.balloon_card;
            RadiusLayout radiusLayout = (RadiusLayout) AbstractC3375o2.c(i, view);
            if (radiusLayout != null) {
                i = R.id.balloon_content;
                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(i, view);
                if (frameLayout2 != null) {
                    i = R.id.balloon_text;
                    VectorTextView vectorTextView = (VectorTextView) AbstractC3375o2.c(i, view);
                    if (vectorTextView != null) {
                        i = R.id.balloon_wrapper;
                        FrameLayout frameLayout3 = (FrameLayout) AbstractC3375o2.c(i, view);
                        if (frameLayout3 != null) {
                            return new BalloonLayoutBodyBinding(frameLayout, frameLayout, imageView, radiusLayout, frameLayout2, vectorTextView, frameLayout3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @NonNull
    public static BalloonLayoutBodyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BalloonLayoutBodyBinding inflate(@NonNull LayoutInflater layoutInflater, ViewGroup viewGroup, boolean z) {
        View viewInflate = layoutInflater.inflate(R.layout.balloon_layout_body, viewGroup, false);
        if (z) {
            viewGroup.addView(viewInflate);
        }
        return bind(viewInflate);
    }

    @Override // androidx.viewbinding.a
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}

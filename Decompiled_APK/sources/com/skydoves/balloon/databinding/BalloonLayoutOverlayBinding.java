package com.skydoves.balloon.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.viewbinding.a;
import com.skydoves.balloon.R;
import com.skydoves.balloon.overlay.BalloonAnchorOverlayView;

/* loaded from: classes3.dex */
public final class BalloonLayoutOverlayBinding implements a {

    @NonNull
    public final BalloonAnchorOverlayView balloonOverlayView;

    @NonNull
    private final BalloonAnchorOverlayView rootView;

    private BalloonLayoutOverlayBinding(@NonNull BalloonAnchorOverlayView balloonAnchorOverlayView, @NonNull BalloonAnchorOverlayView balloonAnchorOverlayView2) {
        this.rootView = balloonAnchorOverlayView;
        this.balloonOverlayView = balloonAnchorOverlayView2;
    }

    @NonNull
    public static BalloonLayoutOverlayBinding bind(@NonNull View view) {
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        BalloonAnchorOverlayView balloonAnchorOverlayView = (BalloonAnchorOverlayView) view;
        return new BalloonLayoutOverlayBinding(balloonAnchorOverlayView, balloonAnchorOverlayView);
    }

    @NonNull
    public static BalloonLayoutOverlayBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BalloonLayoutOverlayBinding inflate(@NonNull LayoutInflater layoutInflater, ViewGroup viewGroup, boolean z) {
        View viewInflate = layoutInflater.inflate(R.layout.balloon_layout_overlay, viewGroup, false);
        if (z) {
            viewGroup.addView(viewInflate);
        }
        return bind(viewInflate);
    }

    @Override // androidx.viewbinding.a
    @NonNull
    public BalloonAnchorOverlayView getRoot() {
        return this.rootView;
    }
}

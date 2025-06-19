package com.quizlet.ads.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.navigation.U;
import com.google.android.gms.ads.nativead.NativeAdView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class NativeAdFragment extends Hilt_NativeAdFragment<com.quizlet.ads.databinding.b> {
    public static final String m;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.ads.viewmodel.a.class), new b(this, 0), new b(this, 2), new b(this, 1));
    public com.quizlet.ads.g k;
    public a l;

    static {
        Intrinsics.checkNotNullExpressionValue("NativeAdFragment", "getSimpleName(...)");
        m = "NativeAdFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        String str = StaticBannerAdFragment.l;
        return StaticBannerAdFragment.l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_native_ad, viewGroup, false);
        int i = R.id.adBadge;
        if (((AppCompatImageView) AbstractC3375o2.c(R.id.adBadge, viewInflate)) != null) {
            i = R.id.adHeader;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.adHeader, viewInflate);
            if (qTextView != null) {
                i = R.id.adImage;
                AppCompatImageView appCompatImageView = (AppCompatImageView) AbstractC3375o2.c(R.id.adImage, viewInflate);
                if (appCompatImageView != null) {
                    i = R.id.adSubtitle;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.adSubtitle, viewInflate);
                    if (qTextView2 != null) {
                        NativeAdView nativeAdView = (NativeAdView) viewInflate;
                        i = R.id.advertiserName;
                        QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.advertiserName, viewInflate);
                        if (qTextView3 != null) {
                            i = R.id.callToActionButton;
                            AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.callToActionButton, viewInflate);
                            if (assemblySecondaryButton != null) {
                                i = R.id.constraintContainer;
                                ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.constraintContainer, viewInflate);
                                if (constraintLayout != null) {
                                    i = R.id.mediaViewFrame;
                                    FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.mediaViewFrame, viewInflate);
                                    if (frameLayout != null) {
                                        com.quizlet.ads.databinding.b bVar = new com.quizlet.ads.databinding.b(nativeAdView, qTextView, appCompatImageView, qTextView2, qTextView3, assemblySecondaryButton, constraintLayout, frameLayout);
                                        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
                                        return bVar;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.ads.viewmodel.a) this.j.getValue()).g.f(getViewLifecycleOwner(), new c(new U(this, 10)));
    }
}

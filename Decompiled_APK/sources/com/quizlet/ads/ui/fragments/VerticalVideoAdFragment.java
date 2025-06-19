package com.quizlet.ads.ui.fragments;

import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.o;
import androidx.navigation.U;
import com.google.android.gms.ads.internal.client.F0;
import com.google.android.gms.ads.m;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.ads.s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O4;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class VerticalVideoAdFragment extends Hilt_VerticalVideoAdFragment<com.quizlet.ads.databinding.e> {
    public static final String m;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.ads.viewmodel.a.class), new j(this, 0), new j(this, 2), new j(this, 1));
    public com.quizlet.ads.g k;
    public a l;

    static {
        Intrinsics.checkNotNullExpressionValue("VerticalVideoAdFragment", "getSimpleName(...)");
        m = "VerticalVideoAdFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_vertical_video_ad, viewGroup, false);
        int i = R.id.adBadge;
        if (((AppCompatImageView) AbstractC3375o2.c(R.id.adBadge, viewInflate)) != null) {
            i = R.id.videoContainer;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.videoContainer, viewInflate);
            if (frameLayout != null) {
                i = R.id.videoContainer916;
                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.videoContainer916, viewInflate);
                if (frameLayout2 != null) {
                    com.quizlet.ads.databinding.e eVar = new com.quizlet.ads.databinding.e((ConstraintLayout) viewInflate, frameLayout, frameLayout2);
                    Intrinsics.checkNotNullExpressionValue(eVar, "inflate(...)");
                    return eVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void T(int i, int i2) throws IllegalAccessException, Resources.NotFoundException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int dimensionPixelOffset = getResources().getDimensionPixelOffset(i2);
        int dimensionPixelOffset2 = getResources().getDimensionPixelOffset(R.dimen.ref_spacing_xsmall);
        o oVar = new o();
        oVar.d(((com.quizlet.ads.databinding.e) J()).a);
        oVar.e(R.id.adBadge, 6, i, 6, dimensionPixelOffset);
        oVar.e(R.id.adBadge, 3, i, 3, dimensionPixelOffset2);
        oVar.a(((com.quizlet.ads.databinding.e) J()).a);
    }

    public final void U(FrameLayout frameLayout) {
        s sVarA;
        com.quizlet.ads.g gVar = this.k;
        if (gVar == null) {
            Intrinsics.m("adsRepository");
            throw null;
        }
        NativeCustomFormatAd nativeCustomFormatAd = gVar.a;
        if (nativeCustomFormatAd != null) {
            nativeCustomFormatAd.recordImpression();
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.j;
            com.quizlet.ads.viewmodel.a aVar = (com.quizlet.ads.viewmodel.a) eVar.getValue();
            m mediaContent = nativeCustomFormatAd.getMediaContent();
            if (mediaContent == null || (sVarA = ((F0) mediaContent).a()) == null || !sVarA.a()) {
                aVar.B();
            } else {
                aVar.getClass();
            }
            ((com.quizlet.ads.viewmodel.a) eVar.getValue()).C(O4.a(nativeCustomFormatAd));
            AbstractC3188k6.c(frameLayout);
            frameLayout.setVisibility(0);
            AbstractC3188k6.c(frameLayout);
            m mediaContent2 = nativeCustomFormatAd.getMediaContent();
            if (mediaContent2 != null) {
                a aVar2 = this.l;
                if (aVar2 != null) {
                    frameLayout.addView((View) aVar2.a(mediaContent2));
                } else {
                    Intrinsics.m("mediaViewCreator");
                    throw null;
                }
            }
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.ads.viewmodel.a) this.j.getValue()).i.f(getViewLifecycleOwner(), new c(new U(this, 13), 0));
    }
}

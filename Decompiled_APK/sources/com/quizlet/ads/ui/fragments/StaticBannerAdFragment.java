package com.quizlet.ads.ui.fragments;

import android.content.Context;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import android.text.method.LinkMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.InlineFontTypefaceSpan;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class StaticBannerAdFragment extends Hilt_StaticBannerAdFragment<com.quizlet.ads.databinding.d> {
    public static final String l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.ads.viewmodel.a.class), new h(this, 0), new h(this, 2), new h(this, 1));
    public com.quizlet.ads.g k;

    static {
        Intrinsics.checkNotNullExpressionValue("StaticBannerAdFragment", "getSimpleName(...)");
        l = "StaticBannerAdFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_static_banner_ad, viewGroup, false);
        int i = R.id.adBadge;
        if (((AppCompatImageView) AbstractC3375o2.c(R.id.adBadge, viewInflate)) != null) {
            i = R.id.adContainer;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.adContainer, viewInflate);
            if (frameLayout != null) {
                i = R.id.studyAdFree;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.studyAdFree, viewInflate);
                if (qTextView != null) {
                    com.quizlet.ads.databinding.d dVar = new com.quizlet.ads.databinding.d(frameLayout, (ConstraintLayout) viewInflate, qTextView);
                    Intrinsics.checkNotNullExpressionValue(dVar, "inflate(...)");
                    return dVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.ads.databinding.d dVar = (com.quizlet.ads.databinding.d) J();
        String string = getString(R.string.study_ad_free);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(string);
        spannableStringBuilder.setSpan(new g(this), 0, spannableStringBuilder.length(), 33);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        spannableStringBuilder.setSpan(new ForegroundColorSpan(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.textColorAccent)), 0, spannableStringBuilder.length(), 33);
        Context contextRequireContext2 = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
        spannableStringBuilder.setSpan(new InlineFontTypefaceSpan(androidx.core.content.res.k.a(contextRequireContext2, com.quizlet.ui.resources.designsystem.generated.a.d)), 0, spannableStringBuilder.length(), 33);
        String string2 = getString(R.string.study_ad_free_text);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        SpannedString spannedStringA = com.quizlet.uicommon.util.a.a(string2, spannableStringBuilder);
        Intrinsics.checkNotNullExpressionValue(spannedStringA, "format(...)");
        dVar.c.setText(spannedStringA);
        ((com.quizlet.ads.databinding.d) J()).c.setMovementMethod(LinkMovementMethod.getInstance());
        ((com.quizlet.ads.viewmodel.a) this.j.getValue()).f.f(getViewLifecycleOwner(), new c(new U(this, 12), (char) 0));
    }
}

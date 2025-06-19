package com.quizlet.ads.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.navigation.U;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class OutStreamVideoAdFragment extends Hilt_OutStreamVideoAdFragment<com.quizlet.ads.databinding.c> {
    public static final String m;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.ads.viewmodel.a.class), new e(this, 0), new e(this, 2), new e(this, 1));
    public com.quizlet.ads.g k;
    public a l;

    static {
        Intrinsics.checkNotNullExpressionValue("OutStreamVideoAdFragment", "getSimpleName(...)");
        m = "OutStreamVideoAdFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_outstream_video_ad, viewGroup, false);
        int i = R.id.adBadge;
        if (((AppCompatImageView) AbstractC3375o2.c(R.id.adBadge, viewInflate)) != null) {
            i = R.id.studyBreakCopy;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.studyBreakCopy, viewInflate);
            if (qTextView != null) {
                i = R.id.videoContainer;
                FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.videoContainer, viewInflate);
                if (frameLayout != null) {
                    com.quizlet.ads.databinding.c cVar = new com.quizlet.ads.databinding.c(frameLayout, (ConstraintLayout) viewInflate, qTextView);
                    Intrinsics.checkNotNullExpressionValue(cVar, "inflate(...)");
                    return cVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.ads.viewmodel.a) this.j.getValue()).h.f(getViewLifecycleOwner(), new c(new U(this, 11), (byte) 0));
    }
}

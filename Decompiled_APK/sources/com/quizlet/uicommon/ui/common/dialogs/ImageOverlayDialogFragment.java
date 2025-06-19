package com.quizlet.uicommon.ui.common.dialogs;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.baseui.base.BaseViewBindingDialogFragment;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes3.dex */
public final class ImageOverlayDialogFragment extends BaseViewBindingDialogFragment<com.quizlet.quizletandroid.ui.common.databinding.b> {
    public static final String x;
    public com.quizlet.qutils.image.loading.a w;

    static {
        Intrinsics.checkNotNullExpressionValue("ImageOverlayDialogFragment", "getSimpleName(...)");
        x = "ImageOverlayDialogFragment";
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_image_overlay, viewGroup, false);
        LinearLayout linearLayout = (LinearLayout) viewInflate;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.imageOverlayView, viewInflate);
        if (imageView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.imageOverlayView)));
        }
        com.quizlet.quizletandroid.ui.common.databinding.b bVar = new com.quizlet.quizletandroid.ui.common.databinding.b(linearLayout, linearLayout, imageView);
        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
        return bVar;
    }

    public final ImageView R() {
        ImageView imageOverlayView = ((com.quizlet.quizletandroid.ui.common.databinding.b) P()).c;
        Intrinsics.checkNotNullExpressionValue(imageOverlayView, "imageOverlayView");
        return imageOverlayView;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        Window window;
        super.onStart();
        Dialog dialog = this.l;
        if (dialog != null && (window = dialog.getWindow()) != null) {
            window.setLayout(-2, -2);
        }
        Bundle arguments = getArguments();
        String string = arguments != null ? arguments.getString("overlayImagePath") : null;
        if (string == null || StringsKt.O(string)) {
            R().setVisibility(8);
            return;
        }
        com.quizlet.qutils.image.loading.a aVar = this.w;
        if (aVar != null) {
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(requireContext()).p(string).p(R(), new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 24), new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(20));
        } else {
            Intrinsics.m("imageLoader");
            throw null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        LinearLayout imageOverlayContainer = ((com.quizlet.quizletandroid.ui.common.databinding.b) P()).b;
        Intrinsics.checkNotNullExpressionValue(imageOverlayContainer, "imageOverlayContainer");
        imageOverlayContainer.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 28));
    }
}

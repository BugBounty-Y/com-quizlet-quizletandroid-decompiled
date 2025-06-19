package com.quizlet.quizletandroid.ui.common.dialogs;

import android.app.Dialog;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import androidx.cardview.widget.CardView;
import androidx.core.widget.NestedScrollView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.baseui.base.BaseViewBindingDialogFragment;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4615t;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class TextOverlayDialogFragment extends BaseViewBindingDialogFragment<C4615t> {
    public static final /* synthetic */ int w = 0;

    static {
        Intrinsics.checkNotNullExpressionValue("TextOverlayDialogFragment", "getSimpleName(...)");
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_text_overlay, viewGroup, false);
        CardView cardView = (CardView) viewInflate;
        int i = R.id.textOverlayScrollView;
        if (((NestedScrollView) AbstractC3375o2.c(R.id.textOverlayScrollView, viewInflate)) != null) {
            i = R.id.textOverlayView;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.textOverlayView, viewInflate);
            if (qTextView != null) {
                C4615t c4615t = new C4615t(cardView, cardView, qTextView);
                Intrinsics.checkNotNullExpressionValue(c4615t, "inflate(...)");
                return c4615t;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Window window;
        Window window2;
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Dialog dialog = this.l;
        if (dialog != null && (window2 = dialog.getWindow()) != null) {
            window2.setBackgroundDrawable(new ColorDrawable(0));
        }
        Dialog dialog2 = this.l;
        if (dialog2 != null && (window = dialog2.getWindow()) != null) {
            window.requestFeature(1);
        }
        return super.onCreateView(inflater, viewGroup, bundle);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        QTextView textOverlayView = ((C4615t) P()).c;
        Intrinsics.checkNotNullExpressionValue(textOverlayView, "textOverlayView");
        Bundle arguments = getArguments();
        textOverlayView.setText(arguments != null ? arguments.getCharSequence("overlayText") : null);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        WindowManager windowManager = requireActivity().getWindowManager();
        Intrinsics.checkNotNullExpressionValue(windowManager, "getWindowManager(...)");
        int height = AbstractC3206m6.b(windowManager).getHeight();
        QTextView textOverlayView = ((C4615t) P()).c;
        Intrinsics.checkNotNullExpressionValue(textOverlayView, "textOverlayView");
        textOverlayView.getViewTreeObserver().addOnGlobalLayoutListener(new com.quizlet.diagrams.text.a(textOverlayView, this, height, 1));
        QTextView textOverlayView2 = ((C4615t) P()).c;
        Intrinsics.checkNotNullExpressionValue(textOverlayView2, "textOverlayView");
        textOverlayView2.setOnClickListener(new h(this, 2));
    }
}

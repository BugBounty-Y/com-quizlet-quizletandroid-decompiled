package com.quizlet.quizletandroid.ui.common.dialogs;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.f;
import com.google.android.material.bottomsheet.h;
import com.quizlet.baseui.base.BaseViewBindingDialogFragment;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4610n;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public abstract class BaseConvertableModalDialogFragment extends BaseViewBindingDialogFragment<C4610n> {
    public final u w;
    public final u x;

    public BaseConvertableModalDialogFragment() {
        final int i = 0;
        this.w = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.common.dialogs.a
            public final /* synthetic */ BaseConvertableModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    default:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                }
            }
        });
        final int i2 = 1;
        this.x = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.common.dialogs.a
            public final /* synthetic */ BaseConvertableModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    default:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                }
            }
        });
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        super.K(bundle);
        return ((Boolean) this.w.getValue()).booleanValue() ? new Dialog(requireContext(), R.style.QuizletDialog) : new h(requireContext());
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.base_convertable_modal_dialog_fragment, viewGroup, false);
        int i = R.id.back;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.back, viewInflate);
        if (frameLayout != null) {
            i = R.id.bottomDrawerHandleImage;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.bottomDrawerHandleImage, viewInflate);
            if (imageView != null) {
                i = R.id.contentFragment;
                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.contentFragment, viewInflate);
                if (frameLayout2 != null) {
                    i = R.id.dividerView;
                    View viewC = AbstractC3375o2.c(R.id.dividerView, viewInflate);
                    if (viewC != null) {
                        i = R.id.modalTitleText;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.modalTitleText, viewInflate);
                        if (qTextView != null) {
                            C4610n c4610n = new C4610n((ConstraintLayout) viewInflate, frameLayout, imageView, frameLayout2, viewC, qTextView);
                            Intrinsics.checkNotNullExpressionValue(c4610n, "inflate(...)");
                            return c4610n;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public abstract View R(LayoutInflater layoutInflater, FrameLayout frameLayout);

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        FrameLayout contentFragment = ((C4610n) P()).d;
        Intrinsics.checkNotNullExpressionValue(contentFragment, "contentFragment");
        ((C4610n) P()).d.addView(R(inflater, contentFragment));
        return viewOnCreateView;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        C4610n c4610n = (C4610n) P();
        c4610n.b.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 1));
        ((C4610n) P()).f.setVisibility(8);
        if (((Boolean) this.w.getValue()).booleanValue()) {
            ((C4610n) P()).e.setVisibility(4);
            return;
        }
        u uVar = this.x;
        ((View) uVar.getValue()).setBackgroundResource(R.drawable.bg_bottom_sheet_dialog_fragment);
        ((C4610n) P()).c.setVisibility(0);
        ((C4610n) P()).b.setVisibility(8);
        BottomSheetBehavior.C((View) uVar.getValue()).w(new f(this, 1));
    }
}

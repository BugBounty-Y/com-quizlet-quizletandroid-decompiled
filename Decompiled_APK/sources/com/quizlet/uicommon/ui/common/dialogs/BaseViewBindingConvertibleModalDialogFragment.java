package com.quizlet.uicommon.ui.common.dialogs;

import android.content.Context;
import android.content.res.Resources;
import android.util.Size;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.quizlet.baseui.base.BaseViewBindingDialogFragment;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public abstract class BaseViewBindingConvertibleModalDialogFragment<T extends androidx.viewbinding.a> extends BaseViewBindingDialogFragment<T> {
    public final u A;
    public final u w;
    public final u x;
    public final b y = b.b;
    public final u z;

    public BaseViewBindingConvertibleModalDialogFragment() {
        final int i = 0;
        this.w = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.a
            public final /* synthetic */ BaseViewBindingConvertibleModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                int i2;
                int i3;
                switch (i) {
                    case 0:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                    case 1:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    case 2:
                        b background = this.b.S();
                        Intrinsics.checkNotNullParameter(background, "background");
                        int iOrdinal = background.ordinal();
                        if (iOrdinal == 0) {
                            i2 = R.style.ConvertibleAssemblyModalDialogTheme_L1;
                        } else if (iOrdinal == 1) {
                            i2 = R.style.ConvertibleAssemblyModalDialogTheme_L2;
                        } else {
                            if (iOrdinal != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i2 = R.style.ConvertibleAssemblyModalDialogTheme_Upsell;
                        }
                        return Integer.valueOf(i2);
                    default:
                        b background2 = this.b.S();
                        Intrinsics.checkNotNullParameter(background2, "background");
                        int iOrdinal2 = background2.ordinal();
                        if (iOrdinal2 == 0) {
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_1;
                        } else if (iOrdinal2 == 1) {
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_2;
                        } else {
                            if (iOrdinal2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_upsell;
                        }
                        return Integer.valueOf(i3);
                }
            }
        });
        final int i2 = 1;
        this.x = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.a
            public final /* synthetic */ BaseViewBindingConvertibleModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                int i22;
                int i3;
                switch (i2) {
                    case 0:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                    case 1:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    case 2:
                        b background = this.b.S();
                        Intrinsics.checkNotNullParameter(background, "background");
                        int iOrdinal = background.ordinal();
                        if (iOrdinal == 0) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L1;
                        } else if (iOrdinal == 1) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L2;
                        } else {
                            if (iOrdinal != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_Upsell;
                        }
                        return Integer.valueOf(i22);
                    default:
                        b background2 = this.b.S();
                        Intrinsics.checkNotNullParameter(background2, "background");
                        int iOrdinal2 = background2.ordinal();
                        if (iOrdinal2 == 0) {
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_1;
                        } else if (iOrdinal2 == 1) {
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_2;
                        } else {
                            if (iOrdinal2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i3 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_upsell;
                        }
                        return Integer.valueOf(i3);
                }
            }
        });
        final int i3 = 2;
        this.z = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.a
            public final /* synthetic */ BaseViewBindingConvertibleModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                int i22;
                int i32;
                switch (i3) {
                    case 0:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                    case 1:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    case 2:
                        b background = this.b.S();
                        Intrinsics.checkNotNullParameter(background, "background");
                        int iOrdinal = background.ordinal();
                        if (iOrdinal == 0) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L1;
                        } else if (iOrdinal == 1) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L2;
                        } else {
                            if (iOrdinal != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_Upsell;
                        }
                        return Integer.valueOf(i22);
                    default:
                        b background2 = this.b.S();
                        Intrinsics.checkNotNullParameter(background2, "background");
                        int iOrdinal2 = background2.ordinal();
                        if (iOrdinal2 == 0) {
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_1;
                        } else if (iOrdinal2 == 1) {
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_2;
                        } else {
                            if (iOrdinal2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_upsell;
                        }
                        return Integer.valueOf(i32);
                }
            }
        });
        final int i4 = 3;
        this.A = kotlin.l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.a
            public final /* synthetic */ BaseViewBindingConvertibleModalDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                int i22;
                int i32;
                switch (i4) {
                    case 0:
                        View view = this.b.getView();
                        Object parent = view != null ? view.getParent() : null;
                        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                        return (View) parent;
                    case 1:
                        Context contextRequireContext = this.b.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return Boolean.valueOf(AbstractC3170i6.i(contextRequireContext));
                    case 2:
                        b background = this.b.S();
                        Intrinsics.checkNotNullParameter(background, "background");
                        int iOrdinal = background.ordinal();
                        if (iOrdinal == 0) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L1;
                        } else if (iOrdinal == 1) {
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_L2;
                        } else {
                            if (iOrdinal != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i22 = R.style.ConvertibleAssemblyModalDialogTheme_Upsell;
                        }
                        return Integer.valueOf(i22);
                    default:
                        b background2 = this.b.S();
                        Intrinsics.checkNotNullParameter(background2, "background");
                        int iOrdinal2 = background2.ordinal();
                        if (iOrdinal2 == 0) {
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_1;
                        } else if (iOrdinal2 == 1) {
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_level_2;
                        } else {
                            if (iOrdinal2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i32 = R.drawable.bg_convertible_assembly_modal_bottom_sheet_upsell;
                        }
                        return Integer.valueOf(i32);
                }
            }
        });
    }

    public abstract void R(FrameLayout frameLayout, AbstractC1136h0 abstractC1136h0);

    public b S() {
        return this.y;
    }

    public final View T() {
        return (View) this.w.getValue();
    }

    public final void U(boolean z) {
        Size size = z ? new Size(getResources().getDimensionPixelSize(R.dimen.dialog_max_width), (int) (Resources.getSystem().getDisplayMetrics().heightPixels * 0.6666667f)) : new Size(getResources().getDimensionPixelSize(R.dimen.dialog_max_width), -2);
        ViewGroup.LayoutParams layoutParams = T().getLayoutParams();
        layoutParams.width = size.getWidth();
        layoutParams.height = size.getHeight();
    }

    public abstract void V();

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        V();
    }
}

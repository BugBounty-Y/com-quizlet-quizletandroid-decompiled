package com.quizlet.uicommon.ui.common.dialogs.info;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class InfoDialogModalFragment extends DialogInterfaceOnCancelListenerC1151t {
    public static final String s;
    public final u q;
    public final u r;

    static {
        Intrinsics.checkNotNullExpressionValue("InfoDialogModalFragment", "getSimpleName(...)");
        s = "InfoDialogModalFragment";
    }

    public InfoDialogModalFragment() {
        final int i = 0;
        this.q = l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.info.a
            public final /* synthetic */ InfoDialogModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                InfoDialogModalFragment infoDialogModalFragment = this.b;
                switch (i) {
                    case 0:
                        String str = InfoDialogModalFragment.s;
                        String string = infoDialogModalFragment.requireArguments().getString("title");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    default:
                        String str2 = InfoDialogModalFragment.s;
                        String string2 = infoDialogModalFragment.requireArguments().getString("info");
                        Intrinsics.e(string2, "null cannot be cast to non-null type kotlin.String");
                        return string2;
                }
            }
        });
        final int i2 = 1;
        this.r = l.b(new Function0(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.info.a
            public final /* synthetic */ InfoDialogModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                InfoDialogModalFragment infoDialogModalFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = InfoDialogModalFragment.s;
                        String string = infoDialogModalFragment.requireArguments().getString("title");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    default:
                        String str2 = InfoDialogModalFragment.s;
                        String string2 = infoDialogModalFragment.requireArguments().getString("info");
                        Intrinsics.e(string2, "null cannot be cast to non-null type kotlin.String");
                        return string2;
                }
            }
        });
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        return new Dialog(requireContext(), R.style.ConvertibleAssemblyModalDialogTheme_L2);
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        ComposeView composeView = new ComposeView(contextRequireContext, null, 6);
        composeView.setContent(new androidx.compose.runtime.internal.d(true, 1666517676, new b(this, 1)));
        return composeView;
    }
}

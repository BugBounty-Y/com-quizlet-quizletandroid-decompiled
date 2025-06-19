package com.quizlet.uicommon.ui.common.dialogs.info;

import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalButtonState;
import java.text.ParseException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class InfoModalFragment extends UnstyledConvertibleModalDialogFragment {
    public com.onetrust.otpublishers.headless.databinding.d E;
    public com.quizlet.login.magiclink.ui.e F;

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        container.addView((ConstraintLayout) d0().b);
    }

    public final InfoModalButtonState c0() {
        InfoModalButtonState infoModalButtonState = (InfoModalButtonState) requireArguments().getParcelable("ARG_BUTTON_STATE");
        if (infoModalButtonState != null) {
            return infoModalButtonState;
        }
        throw new IllegalStateException("Missing required argument (InfoModalButtonState)");
    }

    public final com.onetrust.otpublishers.headless.databinding.d d0() {
        com.onetrust.otpublishers.headless.databinding.d dVar = this.E;
        if (dVar != null) {
            return dVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_info_model_dialog, viewGroup, false);
        int i = R.id.dialog_description_text;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.dialog_description_text, viewInflate);
        if (qTextView != null) {
            i = R.id.dialog_title_text;
            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.dialog_title_text, viewInflate);
            if (qTextView2 != null) {
                View viewC = AbstractC3375o2.c(R.id.drawer_handler_view, viewInflate);
                i = R.id.got_it_button_default;
                View viewC2 = AbstractC3375o2.c(R.id.got_it_button_default, viewInflate);
                if (viewC2 != null) {
                    AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.got_it_button_primary, viewInflate);
                    i = R.id.got_it_button_secondary;
                    AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.got_it_button_secondary, viewInflate);
                    if (assemblySecondaryButton != null) {
                        this.E = new com.onetrust.otpublishers.headless.databinding.d((ConstraintLayout) viewInflate, qTextView, qTextView2, viewC, viewC2, assemblyPrimaryButton, assemblySecondaryButton);
                        return super.onCreateView(inflater, viewGroup, bundle);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.E = null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) throws ParseException {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        com.quizlet.login.magiclink.ui.e eVar = this.F;
        if (eVar != null) {
            eVar.invoke();
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        this.B = requireArguments().getBoolean("ARG_SKIP_COLLAPSED");
        super.onStart();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        final int i = 0;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        View gotItButtonDefault = d0().e;
        Intrinsics.checkNotNullExpressionValue(gotItButtonDefault, "gotItButtonDefault");
        gotItButtonDefault.setVisibility(c0().equals(InfoModalButtonState.Default.a) ? 0 : 8);
        AssemblySecondaryButton gotItButtonSecondary = (AssemblySecondaryButton) d0().g;
        Intrinsics.checkNotNullExpressionValue(gotItButtonSecondary, "gotItButtonSecondary");
        gotItButtonSecondary.setVisibility(c0().equals(InfoModalButtonState.Secondary.a) ? 0 : 8);
        com.onetrust.otpublishers.headless.databinding.d dVarD0 = d0();
        InfoModalButtonState.Primary primary = InfoModalButtonState.Primary.a;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) dVarD0.f;
        if (assemblyPrimaryButton != null) {
            assemblyPrimaryButton.setVisibility(c0().equals(primary) ? 0 : 8);
        }
        if (!X() && c0().equals(primary)) {
            View gotItButtonDefault2 = d0().e;
            Intrinsics.checkNotNullExpressionValue(gotItButtonDefault2, "gotItButtonDefault");
            gotItButtonDefault2.setVisibility(c0().equals(primary) ? 0 : 8);
        }
        com.onetrust.otpublishers.headless.databinding.d dVarD02 = d0();
        CharSequence charSequence = requireArguments().getCharSequence("ARG_TITLE");
        if (charSequence == null) {
            throw new IllegalStateException("Missing required argument (Title)");
        }
        ((QTextView) dVarD02.d).setText(charSequence);
        com.onetrust.otpublishers.headless.databinding.d dVarD03 = d0();
        CharSequence charSequence2 = requireArguments().getCharSequence("ARG_DESCRIPTION");
        if (charSequence2 == null) {
            throw new IllegalStateException("Missing required argument (Description)");
        }
        ((QTextView) dVarD03.c).setText(charSequence2);
        com.onetrust.otpublishers.headless.databinding.d dVarD04 = d0();
        CharSequence charSequence3 = requireArguments().getCharSequence("ARG_BUTTON_TEXT", "");
        Intrinsics.checkNotNullExpressionValue(charSequence3, "getCharSequence(...)");
        if (charSequence3.length() == 0) {
            charSequence3 = requireContext().getString(R.string.got_it);
            Intrinsics.checkNotNullExpressionValue(charSequence3, "getString(...)");
        }
        ((com.quizlet.assembly.widgets.buttons.d) dVarD04.e).setText(charSequence3);
        ((AssemblySecondaryButton) dVarD04.g).setText(charSequence3);
        AssemblyPrimaryButton assemblyPrimaryButton2 = (AssemblyPrimaryButton) dVarD04.f;
        if (assemblyPrimaryButton2 != null) {
            assemblyPrimaryButton2.setText(charSequence3);
            Unit unit = Unit.a;
        }
        d0().e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.info.f
            public final /* synthetic */ InfoModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        this.b.H(false, false);
                        break;
                    case 1:
                        this.b.H(false, false);
                        break;
                    default:
                        this.b.H(false, false);
                        break;
                }
            }
        });
        final int i2 = 1;
        ((AssemblySecondaryButton) d0().g).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.info.f
            public final /* synthetic */ InfoModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        this.b.H(false, false);
                        break;
                    case 1:
                        this.b.H(false, false);
                        break;
                    default:
                        this.b.H(false, false);
                        break;
                }
            }
        });
        AssemblyPrimaryButton assemblyPrimaryButton3 = (AssemblyPrimaryButton) d0().f;
        if (assemblyPrimaryButton3 != null) {
            final int i3 = 2;
            assemblyPrimaryButton3.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.uicommon.ui.common.dialogs.info.f
                public final /* synthetic */ InfoModalFragment b;

                {
                    this.b = this;
                }

                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    switch (i3) {
                        case 0:
                            this.b.H(false, false);
                            break;
                        case 1:
                            this.b.H(false, false);
                            break;
                        default:
                            this.b.H(false, false);
                            break;
                    }
                }
            });
        }
    }
}

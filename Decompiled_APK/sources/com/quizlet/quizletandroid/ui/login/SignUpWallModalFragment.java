package com.quizlet.quizletandroid.ui.login;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.measurement.AbstractC3088z1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class SignUpWallModalFragment extends Hilt_SignUpWallModalFragment {
    public static final String X;
    public com.quizlet.local.ormlite.models.term.b J;
    public com.quizlet.features.infra.legacyadapter.databinding.f K;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e L;
    public final kotlin.u M;
    public final com.quizlet.uicommon.ui.common.dialogs.b V;
    public final boolean W;

    static {
        Intrinsics.checkNotNullExpressionValue("SignUpWallModalFragment", "getSimpleName(...)");
        X = "SignUpWallModalFragment";
    }

    public SignUpWallModalFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 12), 13));
        this.L = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.signupwall.viewmodel.a.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 15), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 5), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 16));
        this.M = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 19));
        this.V = com.quizlet.uicommon.ui.common.dialogs.b.a;
        this.W = true;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        com.quizlet.features.infra.legacyadapter.databinding.f fVar = this.K;
        if (fVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        container.addView((ConstraintLayout) fVar.c);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final com.quizlet.uicommon.ui.common.dialogs.b S() {
        return this.V;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment
    public final boolean a0() {
        return this.W;
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_signup_wall, viewGroup, false);
        int i = R.id.drawerHandlerView;
        View viewC = AbstractC3375o2.c(R.id.drawerHandlerView, viewInflate);
        if (viewC != null) {
            i = R.id.getStartedButton;
            AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.getStartedButton, viewInflate);
            if (assemblyPrimaryButton != null) {
                i = R.id.loginOption;
                TextView textView = (TextView) AbstractC3375o2.c(R.id.loginOption, viewInflate);
                if (textView != null) {
                    i = R.id.signupWallTitle;
                    if (((TextView) AbstractC3375o2.c(R.id.signupWallTitle, viewInflate)) != null) {
                        this.K = new com.quizlet.features.infra.legacyadapter.databinding.f((ConstraintLayout) viewInflate, (Object) viewC, (View) assemblyPrimaryButton, (Object) textView, 2);
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
        this.K = null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        ((com.quizlet.login.signupwall.viewmodel.a) this.L.getValue()).c.a();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.features.infra.legacyadapter.databinding.f fVar = this.K;
        if (fVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        final int i = 0;
        ((TextView) fVar.e).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.x
            public final /* synthetic */ SignUpWallModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                SignUpWallModalFragment signUpWallModalFragment = this.b;
                switch (i) {
                    case 0:
                        String str = SignUpWallModalFragment.X;
                        com.quizlet.login.signupwall.viewmodel.a aVar = (com.quizlet.login.signupwall.viewmodel.a) signUpWallModalFragment.L.getValue();
                        aVar.c.b();
                        aVar.d.j(com.quizlet.login.signupwall.a.b);
                        break;
                    default:
                        String str2 = SignUpWallModalFragment.X;
                        com.quizlet.login.signupwall.viewmodel.a aVar2 = (com.quizlet.login.signupwall.viewmodel.a) signUpWallModalFragment.L.getValue();
                        aVar2.c.d();
                        aVar2.d.j(com.quizlet.login.signupwall.a.a);
                        break;
                }
            }
        });
        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = this.K;
        if (fVar2 == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        final int i2 = 1;
        ((AssemblyPrimaryButton) fVar2.d).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.login.x
            public final /* synthetic */ SignUpWallModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                SignUpWallModalFragment signUpWallModalFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = SignUpWallModalFragment.X;
                        com.quizlet.login.signupwall.viewmodel.a aVar = (com.quizlet.login.signupwall.viewmodel.a) signUpWallModalFragment.L.getValue();
                        aVar.c.b();
                        aVar.d.j(com.quizlet.login.signupwall.a.b);
                        break;
                    default:
                        String str2 = SignUpWallModalFragment.X;
                        com.quizlet.login.signupwall.viewmodel.a aVar2 = (com.quizlet.login.signupwall.viewmodel.a) signUpWallModalFragment.L.getValue();
                        aVar2.c.d();
                        aVar2.d.j(com.quizlet.login.signupwall.a.a);
                        break;
                }
            }
        });
        String string = getResources().getString(R.string.signup_wall_login_option);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        String string2 = getResources().getString(R.string.login);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        int iA = com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.AssemblyTwilight500);
        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = this.K;
        if (fVar3 == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        ((TextView) fVar3.e).setText(AbstractC3088z1.b(string, kotlin.collections.A.b(new com.quizlet.qutils.string.h(string2, iA))));
        ((com.quizlet.login.signupwall.viewmodel.a) this.L.getValue()).d.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, this, SignUpWallModalFragment.class, "setupNavigation", "setupNavigation(Lcom/quizlet/login/signupwall/SignUpWallNavigationState;)V", 0, 19)));
    }
}

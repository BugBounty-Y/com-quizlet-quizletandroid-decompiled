package com.quizlet.upgrade.upsell.ui;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ScrollView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.uicommon.ui.common.views.QuizletPlusLogo;
import java.io.Serializable;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class UpsellModalFragment extends Hilt_UpsellModalFragment {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e J;
    public com.quizlet.login.common.interactors.d K;
    public androidx.activity.result.b L;
    public final boolean M;
    public final com.quizlet.uicommon.ui.common.dialogs.b V;
    public com.onetrust.otpublishers.headless.databinding.d W;
    public final u X;
    public final u Y;
    public final u Z;
    public final u c1;
    public final u d1;
    public final u e1;
    public final u f1;

    public UpsellModalFragment() {
        k kVarA = l.a(m.c, new t(new t(this, 14), 15));
        this.J = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.upsell.viewmodel.c.class), new i(kVarA, 23), new com.quizlet.upgrade.ui.fragment.m(1, this, kVarA), new i(kVarA, 24));
        this.M = true;
        this.V = com.quizlet.uicommon.ui.common.dialogs.b.c;
        final int i = 0;
        this.X = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i2 = 1;
        this.Y = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i3 = 2;
        this.Z = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i4 = 3;
        this.c1 = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i4) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i5 = 4;
        this.d1 = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i5) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i6 = 5;
        this.e1 = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i6) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
        final int i7 = 6;
        this.f1 = l.b(new Function0(this) { // from class: com.quizlet.upgrade.upsell.ui.b
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i7) {
                    case 0:
                        Serializable serializable = this.b.requireArguments().getSerializable(DBUserFields.Names.USER_UPGRADE_TYPE);
                        Intrinsics.e(serializable, "null cannot be cast to non-null type com.quizlet.upgrade.upsell.data.UpsellType");
                        return (com.quizlet.upgrade.upsell.data.a) serializable;
                    case 1:
                        String string = this.b.requireArguments().getString("source");
                        Intrinsics.e(string, "null cannot be cast to non-null type kotlin.String");
                        return string;
                    case 2:
                        Serializable serializable2 = this.b.requireArguments().getSerializable("navigationSource");
                        Intrinsics.e(serializable2, "null cannot be cast to non-null type com.quizlet.features.infra.models.upgrade.UpgradeNavigationSource");
                        return (com.quizlet.features.infra.models.upgrade.a) serializable2;
                    case 3:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.qutils.string.f fVar = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment.X.getValue()).a;
                        Context contextRequireContext = upsellModalFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        return fVar.c(contextRequireContext);
                    case 4:
                        UpsellModalFragment upsellModalFragment2 = this.b;
                        com.quizlet.qutils.string.f fVar2 = ((com.quizlet.upgrade.upsell.data.a) upsellModalFragment2.X.getValue()).b;
                        Context contextRequireContext2 = upsellModalFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        return fVar2.c(contextRequireContext2);
                    case 5:
                        ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).getClass();
                        return null;
                    default:
                        return ((com.quizlet.upgrade.upsell.data.a) this.b.X.getValue()).c;
                }
            }
        });
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void G() {
        com.quizlet.login.common.interactors.d dVar = this.K;
        if (dVar != null) {
            dVar.l();
        }
        H(false, false);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void J() {
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.cancel();
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        container.addView((ConstraintLayout) f0().b);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final com.quizlet.uicommon.ui.common.dialogs.b S() {
        return this.V;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment
    public final boolean a0() {
        return this.M;
    }

    public final com.onetrust.otpublishers.headless.databinding.d f0() {
        com.onetrust.otpublishers.headless.databinding.d dVar = this.W;
        if (dVar != null) {
            return dVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        com.quizlet.login.common.interactors.d dVar = this.K;
        if (dVar != null) {
            dVar.l();
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.L = registerForActivityResult(new androidx.activity.result.contract.b(4), requireActivity().getActivityResultRegistry(), new androidx.activity.compose.b(this, 8));
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_upsell_modal, viewGroup, false);
        int i = R.id.closeButton;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.closeButton, viewInflate);
        if (imageView != null) {
            i = R.id.disclaimerText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.disclaimerText, viewInflate);
            if (qTextView != null) {
                i = R.id.endGuideline;
                if (((Guideline) AbstractC3375o2.c(R.id.endGuideline, viewInflate)) != null) {
                    i = R.id.quizletPlusLogo;
                    if (((QuizletPlusLogo) AbstractC3375o2.c(R.id.quizletPlusLogo, viewInflate)) != null) {
                        i = R.id.scrollableContainer;
                        if (((ScrollView) AbstractC3375o2.c(R.id.scrollableContainer, viewInflate)) != null) {
                            i = R.id.startGuideline;
                            if (((Guideline) AbstractC3375o2.c(R.id.startGuideline, viewInflate)) != null) {
                                i = R.id.subtitleText;
                                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.subtitleText, viewInflate);
                                if (qTextView2 != null) {
                                    i = R.id.titleText;
                                    QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.titleText, viewInflate);
                                    if (qTextView3 != null) {
                                        i = R.id.upsellButton;
                                        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.upsellButton, viewInflate);
                                        if (assemblyPrimaryButton != null) {
                                            i = R.id.valuePropsLayout;
                                            View viewC = AbstractC3375o2.c(R.id.valuePropsLayout, viewInflate);
                                            if (viewC != null) {
                                                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.valuePropOneIcon, viewC);
                                                QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.valuePropOneText, viewC);
                                                ImageView imageView3 = (ImageView) AbstractC3375o2.c(R.id.valuePropThreeIcon, viewC);
                                                QTextView qTextView5 = (QTextView) AbstractC3375o2.c(R.id.valuePropThreeText, viewC);
                                                ImageView imageView4 = (ImageView) AbstractC3375o2.c(R.id.valuePropTwoIcon, viewC);
                                                QTextView qTextView6 = (QTextView) AbstractC3375o2.c(R.id.valuePropTwoText, viewC);
                                                this.W = new com.onetrust.otpublishers.headless.databinding.d((ConstraintLayout) viewInflate, imageView, qTextView, qTextView2, qTextView3, assemblyPrimaryButton, new com.onetrust.otpublishers.headless.databinding.d((ConstraintLayout) viewC, imageView2, qTextView4, imageView3, qTextView5, imageView4, qTextView6, 6), 5);
                                                return super.onCreateView(inflater, viewGroup, bundle);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.W = null;
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDetach() {
        super.onDetach();
        this.K = null;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new d(this, null), 3);
        J viewLifecycleOwner2 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner2, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner2), null, null, new g(this, null), 3);
        ImageView closeButton = (ImageView) f0().d;
        Intrinsics.checkNotNullExpressionValue(closeButton, "closeButton");
        closeButton.setVisibility(!X() ? 0 : 8);
        ConstraintLayout constraintLayout = (ConstraintLayout) ((com.onetrust.otpublishers.headless.databinding.d) f0().h).b;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        constraintLayout.setVisibility(!X() ? 0 : 8);
        final int i = 0;
        ((ImageView) f0().d).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.upgrade.upsell.ui.a
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        this.b.G();
                        break;
                    default:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.login.common.interactors.d dVar = upsellModalFragment.K;
                        if (dVar != null) {
                            q qVar = (q) ((com.google.android.gms.measurement.internal.J) dVar.b).e;
                            EventLoggerExt.c((EventLogger) qVar.b, new com.quizlet.features.notes.logging.c("explanations_upsell_upgrade_cta_clicked", 22));
                        }
                        com.quizlet.upgrade.upsell.viewmodel.c cVar = (com.quizlet.upgrade.upsell.viewmodel.c) upsellModalFragment.J.getValue();
                        cVar.getClass();
                        E.A(p0.j(cVar), null, null, new com.quizlet.upgrade.upsell.viewmodel.b(cVar, null), 3);
                        break;
                }
            }
        });
        final int i2 = 1;
        ((AssemblyPrimaryButton) f0().g).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.upgrade.upsell.ui.a
            public final /* synthetic */ UpsellModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        this.b.G();
                        break;
                    default:
                        UpsellModalFragment upsellModalFragment = this.b;
                        com.quizlet.login.common.interactors.d dVar = upsellModalFragment.K;
                        if (dVar != null) {
                            q qVar = (q) ((com.google.android.gms.measurement.internal.J) dVar.b).e;
                            EventLoggerExt.c((EventLogger) qVar.b, new com.quizlet.features.notes.logging.c("explanations_upsell_upgrade_cta_clicked", 22));
                        }
                        com.quizlet.upgrade.upsell.viewmodel.c cVar = (com.quizlet.upgrade.upsell.viewmodel.c) upsellModalFragment.J.getValue();
                        cVar.getClass();
                        E.A(p0.j(cVar), null, null, new com.quizlet.upgrade.upsell.viewmodel.b(cVar, null), 3);
                        break;
                }
            }
        });
        com.onetrust.otpublishers.headless.databinding.d dVarF0 = f0();
        ((QTextView) dVarF0.f).setText((CharSequence) this.c1.getValue());
        ((QTextView) dVarF0.e).setText((CharSequence) this.d1.getValue());
        u uVar = this.e1;
        CharSequence charSequence = (CharSequence) uVar.getValue();
        QTextView disclaimerText = (QTextView) dVarF0.c;
        disclaimerText.setText(charSequence);
        Intrinsics.checkNotNullExpressionValue(disclaimerText, "disclaimerText");
        disclaimerText.setVisibility(((CharSequence) uVar.getValue()) != null ? 0 : 8);
        com.onetrust.otpublishers.headless.databinding.d dVarF02 = f0();
        u uVar2 = this.f1;
        com.quizlet.upgrade.upsell.data.b bVar = ((com.quizlet.upgrade.upsell.data.c) uVar2.getValue()).a;
        com.onetrust.otpublishers.headless.databinding.d dVar = (com.onetrust.otpublishers.headless.databinding.d) dVarF02.h;
        ImageView imageView = (ImageView) dVar.d;
        if (imageView != null) {
            imageView.setImageResource(bVar.a);
        }
        QTextView qTextView = (QTextView) dVar.c;
        if (qTextView != null) {
            qTextView.setText(bVar.b);
        }
        com.quizlet.upgrade.upsell.data.b bVar2 = ((com.quizlet.upgrade.upsell.data.c) uVar2.getValue()).b;
        ImageView imageView2 = (ImageView) dVar.g;
        if (imageView2 != null) {
            imageView2.setImageResource(bVar2.a);
        }
        QTextView qTextView2 = (QTextView) dVar.h;
        if (qTextView2 != null) {
            qTextView2.setText(bVar2.b);
        }
        com.quizlet.upgrade.upsell.data.b bVar3 = ((com.quizlet.upgrade.upsell.data.c) uVar2.getValue()).c;
        ImageView imageView3 = (ImageView) dVar.e;
        if (imageView3 != null) {
            imageView3.setImageResource(bVar3.a);
        }
        QTextView qTextView3 = (QTextView) dVar.f;
        if (qTextView3 != null) {
            qTextView3.setText(bVar3.b);
        }
        com.quizlet.login.common.interactors.d dVar2 = this.K;
        if (dVar2 != null) {
            EventLoggerExt.c((EventLogger) ((q) ((com.google.android.gms.measurement.internal.J) dVar2.b).e).b, new com.quizlet.features.notes.logging.c("explanations_upsell_viewed", 22));
        }
    }
}

package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.FrameLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityCenterModalFragment extends Hilt_ActivityCenterModalFragment implements c {
    public static final String K;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e I;
    public final u J;

    static {
        Intrinsics.checkNotNullExpressionValue("ActivityCenterModalFragment", "getSimpleName(...)");
        K = "ActivityCenterModalFragment";
    }

    public ActivityCenterModalFragment() {
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 4), 5));
        this.I = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.infra.snackbar.viewmodel.c.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 4), new h(this, kVarA, 0), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 5));
        this.J = l.b(new com.quizlet.login.magiclink.ui.e(this, 7));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        ActivityCenterFragment activityCenterFragment = new ActivityCenterFragment();
        Bundle bundle = new Bundle();
        bundle.putBoolean("ARG_SHOULD_SHOW_TOOLBAR", false);
        activityCenterFragment.setArguments(bundle);
        fragmentManager.getClass();
        C1121a c1121a = new C1121a(fragmentManager);
        c1121a.l(R.id.contentFragment, activityCenterFragment, ActivityCenterFragment.n);
        c1121a.g();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final String W() {
        return (String) this.J.getValue();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        Fragment targetFragment = getTargetFragment();
        if (targetFragment != null) {
            targetFragment.onActivityResult(getTargetRequestCode(), -1, null);
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new g(this, null), 3);
    }
}

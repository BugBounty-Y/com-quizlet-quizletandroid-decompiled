package com.quizlet.login.magiclink.navigation;

import android.os.Bundle;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.features.infra.navigation.n;
import com.quizlet.login.magiclink.ui.MagicLinkLogOutDialogFragment;
import com.quizlet.login.magiclink.ui.MagicLinkSwitchAccountDialogFragment;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements n {
    @Override // com.quizlet.features.infra.navigation.n
    public final void C(AbstractC1136h0 fragmentManager, EnumC4167t0 logoutWarning) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(logoutWarning, "logoutWarning");
        String str = MagicLinkLogOutDialogFragment.x;
        Intrinsics.checkNotNullParameter(logoutWarning, "logoutWarning");
        MagicLinkLogOutDialogFragment magicLinkLogOutDialogFragment = new MagicLinkLogOutDialogFragment();
        Bundle bundle = new Bundle();
        bundle.putSerializable("ARG_LOGOUT_WARNING", logoutWarning);
        magicLinkLogOutDialogFragment.setArguments(bundle);
        magicLinkLogOutDialogFragment.O(fragmentManager, MagicLinkLogOutDialogFragment.x);
    }

    @Override // com.quizlet.features.infra.navigation.n
    public final void h(AbstractC1136h0 fragmentManager, String magicLinkCode) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        String str = MagicLinkSwitchAccountDialogFragment.x;
        Fragment fragmentE = fragmentManager.E(str);
        MagicLinkSwitchAccountDialogFragment magicLinkSwitchAccountDialogFragment = fragmentE instanceof MagicLinkSwitchAccountDialogFragment ? (MagicLinkSwitchAccountDialogFragment) fragmentE : null;
        if (magicLinkSwitchAccountDialogFragment != null) {
            magicLinkSwitchAccountDialogFragment.P();
            magicLinkSwitchAccountDialogFragment.H(true, false);
        }
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        MagicLinkSwitchAccountDialogFragment magicLinkSwitchAccountDialogFragment2 = new MagicLinkSwitchAccountDialogFragment();
        magicLinkSwitchAccountDialogFragment2.setArguments(AbstractC3206m6.a(new Pair("ARG_MAGIC_LINK_CODE", magicLinkCode)));
        magicLinkSwitchAccountDialogFragment2.O(fragmentManager, str);
    }
}

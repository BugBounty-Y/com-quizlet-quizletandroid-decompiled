package com.quizlet.edgy.navigation;

import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.edgy.ui.fragment.EdgyModalFragment;
import com.quizlet.features.infra.navigation.g;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements g {
    @Override // com.quizlet.features.infra.navigation.g
    public final void f(AbstractC1136h0 fragmentManager, boolean z) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        EdgyModalFragment edgyModalFragment = new EdgyModalFragment();
        edgyModalFragment.setArguments(AbstractC3206m6.a(new Pair("ARG_SET_RESULT_ON_DISMISS", Boolean.valueOf(z))));
        edgyModalFragment.O(fragmentManager, EdgyModalFragment.L);
    }
}

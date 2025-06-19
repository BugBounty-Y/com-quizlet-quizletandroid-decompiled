package com.onetrust.otpublishers.headless.UI.Helper;

import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.v0;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class CustomLinearLayoutManager extends LinearLayoutManager {
    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void h0(v0 recycler, B0 state) {
        Intrinsics.checkNotNullParameter(recycler, "recycler");
        Intrinsics.checkNotNullParameter(state, "state");
        try {
            super.h0(recycler, state);
        } catch (IndexOutOfBoundsException e) {
            OTLogger.c(null, 6, "error in layoutManger" + e.getMessage());
        }
    }
}

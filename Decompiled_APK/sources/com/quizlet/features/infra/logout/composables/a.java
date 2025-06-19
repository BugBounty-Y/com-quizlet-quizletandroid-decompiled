package com.quizlet.features.infra.logout.composables;

import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.EnumC4167t0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final x a;
    public final x b;

    public a(x subscriptionPendingWarningModalState, x unsavedDraftsWarningModalState) {
        Intrinsics.checkNotNullParameter(subscriptionPendingWarningModalState, "subscriptionPendingWarningModalState");
        Intrinsics.checkNotNullParameter(unsavedDraftsWarningModalState, "unsavedDraftsWarningModalState");
        this.a = subscriptionPendingWarningModalState;
        this.b = unsavedDraftsWarningModalState;
    }

    public final void a(EnumC4167t0 type) {
        Intrinsics.checkNotNullParameter(type, "type");
        int iOrdinal = type.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                x.d(this.a);
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                x.d(this.b);
            }
        }
    }
}

package com.quizlet.features.infra.logout.viewmodels;

import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.quizletandroid.managers.u;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.scheduling.e;
import kotlinx.coroutines.y0;

/* loaded from: classes3.dex */
public final class d implements a {
    public final u a;
    public final e b;
    public final kotlinx.coroutines.internal.d c;
    public final kotlinx.coroutines.internal.d d;
    public final d0 e;
    public final d0 f;

    public d(u logoutManager, e defaultDispatcher, AbstractC5040y mainDispatcher) {
        Intrinsics.checkNotNullParameter(logoutManager, "logoutManager");
        Intrinsics.checkNotNullParameter(defaultDispatcher, "defaultDispatcher");
        Intrinsics.checkNotNullParameter(mainDispatcher, "mainDispatcher");
        this.a = logoutManager;
        this.b = defaultDispatcher;
        this.c = E.c(defaultDispatcher);
        this.d = E.c(mainDispatcher);
        this.e = e0.b(0, 1, null, 5);
        this.f = e0.b(0, 1, null, 5);
    }

    public final y0 a(boolean z) {
        return E.A(this.c, null, null, new c(this, z, null), 3);
    }

    @Override // com.quizlet.features.infra.logout.viewmodels.a
    public final void v(EnumC4167t0 warningType) {
        Intrinsics.checkNotNullParameter(warningType, "warningType");
        int iOrdinal = warningType.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                a(true);
                return;
            } else if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
        }
        E.A(this.d, null, null, new b(this, null), 3);
        this.e.h(Unit.a);
    }
}

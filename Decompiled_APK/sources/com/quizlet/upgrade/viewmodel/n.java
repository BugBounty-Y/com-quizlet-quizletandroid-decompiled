package com.quizlet.upgrade.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class n extends com.quizlet.viewmodel.b {
    public final com.lyft.android.scissors.b c;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d d;
    public final Y e;
    public final X f;
    public final X g;
    public final Y h;

    public n(m0 savedStateHandle, com.lyft.android.scissors.b billingUserManager, com.quizlet.features.emailconfirmation.logging.a billingEventLogger, com.onetrust.otpublishers.headless.UI.TVUI.datautils.d upgradePurchaseManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
        Intrinsics.checkNotNullParameter(billingEventLogger, "billingEventLogger");
        Intrinsics.checkNotNullParameter(upgradePurchaseManager, "upgradePurchaseManager");
        this.c = billingUserManager;
        this.d = upgradePurchaseManager;
        this.e = new Y();
        this.f = new X(1);
        this.g = new X(1);
        this.h = new Y();
        String str = (String) savedStateHandle.a("UpgradeSource");
        upgradePurchaseManager.b = str;
        E.A(p0.j(this), null, null, new m(this, null), 3);
        billingEventLogger.a.F("upgrade_upgrade_click", str);
    }

    public final void B(Throwable error) {
        Intrinsics.checkNotNullParameter(error, "throwable");
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = this.d;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(error, "throwable");
        com.quizlet.features.emailconfirmation.logging.a aVar = (com.quizlet.features.emailconfirmation.logging.a) dVar.c;
        Intrinsics.checkNotNullParameter(error, "error");
        aVar.a.E("upgrade_error", error.getMessage());
        ((Y) dVar.e).j(com.quizlet.upgrade.manager.f.b);
        ((X) dVar.f).j(com.quizlet.upgrade.manager.c.a);
        timber.log.c.a.e(error);
    }
}

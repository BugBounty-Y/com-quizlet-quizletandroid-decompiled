package com.braze.ui;

import com.braze.BrazeUser;
import com.braze.events.IValueCallback;
import com.braze.ui.UserJavascriptInterfaceBase;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements IValueCallback, com.google.android.gms.ads.formats.c {
    public final /* synthetic */ Function1 a;

    public /* synthetic */ h(Function1 function1) {
        this.a = function1;
    }

    @Override // com.google.android.gms.ads.formats.c
    public void a(AdManagerAdView it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        this.a.invoke(it2);
    }

    @Override // com.braze.events.IValueCallback
    public void onSuccess(Object obj) {
        UserJavascriptInterfaceBase.Companion.runOnUser$lambda$0(this.a, (BrazeUser) obj);
    }
}

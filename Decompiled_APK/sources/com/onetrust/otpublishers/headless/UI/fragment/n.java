package com.onetrust.otpublishers.headless.UI.fragment;

import androidx.appcompat.widget.InterfaceC0078c1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements InterfaceC0078c1 {
    public final /* synthetic */ s a;

    public /* synthetic */ n(s sVar) {
        this.a = sVar;
    }

    @Override // androidx.appcompat.widget.InterfaceC0078c1
    public void onClose() {
        s this$0 = this.a;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = this$0.S();
        dVarS.getClass();
        Intrinsics.checkNotNullParameter("", "query");
        dVarS.k = "";
        dVarS.B();
    }
}

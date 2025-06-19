package com.onetrust.otpublishers.headless.UI.fragment;

import androidx.appcompat.widget.InterfaceC0078c1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class w implements InterfaceC0078c1 {
    public final /* synthetic */ D a;

    public /* synthetic */ w(D d) {
        this.a = d;
    }

    public void a(HashMap selectedMap) {
        com.google.firebase.perf.logging.b bVar = D.D;
        D this$0 = this.a;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(selectedMap, "selectedMap");
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = this$0.X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(selectedMap, "selectedMap");
        (eVarX.C() ? eVarX.k : eVarX.l).l(selectedMap);
        eVarX.D();
        this$0.W(!selectedMap.isEmpty(), (com.onetrust.otpublishers.headless.UI.DataModels.l) AbstractC3665l4.a(this$0.X().h));
    }

    @Override // androidx.appcompat.widget.InterfaceC0078c1
    public void onClose() {
        com.google.firebase.perf.logging.b bVar = D.D;
        D this$0 = this.a;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = this$0.X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter("", "newSearchQuery");
        eVarX.e = "";
        eVarX.D();
    }
}

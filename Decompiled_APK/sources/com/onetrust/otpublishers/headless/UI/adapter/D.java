package com.onetrust.otpublishers.headless.UI.adapter;

import android.widget.RelativeLayout;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3681n4;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D extends F0 {
    public final com.onetrust.otpublishers.headless.databinding.e a;
    public final com.onetrust.otpublishers.headless.UI.DataModels.l b;
    public final OTConfiguration c;
    public final com.onetrust.otpublishers.headless.UI.fragment.E d;
    public final com.onetrust.otpublishers.headless.UI.fragment.F e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(com.onetrust.otpublishers.headless.databinding.e binding, com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.fragment.E onItemToggleCheckedChange, com.onetrust.otpublishers.headless.UI.fragment.F onItemClicked) {
        super((RelativeLayout) binding.b);
        Intrinsics.checkNotNullParameter(binding, "binding");
        Intrinsics.checkNotNullParameter(vendorListData, "vendorListData");
        Intrinsics.checkNotNullParameter(onItemToggleCheckedChange, "onItemToggleCheckedChange");
        Intrinsics.checkNotNullParameter(onItemClicked, "onItemClicked");
        this.a = binding;
        this.b = vendorListData;
        this.c = oTConfiguration;
        this.d = onItemToggleCheckedChange;
        this.e = onItemClicked;
    }

    public final void c(boolean z) {
        SwitchCompat switchCompat = (SwitchCompat) this.a.i;
        com.onetrust.otpublishers.headless.UI.DataModels.l lVar = this.b;
        String str = z ? lVar.g : lVar.h;
        Intrinsics.checkNotNullExpressionValue(switchCompat, "");
        AbstractC3681n4.a(switchCompat, lVar.f, str);
    }
}

package com.onetrust.otpublishers.headless.UI.adapter;

import android.widget.RelativeLayout;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class L extends F0 {
    public final com.onetrust.otpublishers.headless.databinding.d a;
    public final com.onetrust.otpublishers.headless.UI.DataModels.l b;
    public final OTConfiguration c;
    public final com.onetrust.otpublishers.headless.UI.fragment.E d;
    public final com.onetrust.otpublishers.headless.UI.fragment.F e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(com.onetrust.otpublishers.headless.databinding.d binding, com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.fragment.E onItemToggleCheckedChange, com.onetrust.otpublishers.headless.UI.fragment.F onItemClicked) {
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
}

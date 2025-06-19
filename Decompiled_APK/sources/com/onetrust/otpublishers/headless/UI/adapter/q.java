package com.onetrust.otpublishers.headless.UI.adapter;

import android.widget.RelativeLayout;
import androidx.compose.ui.text.C0981a;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q extends F0 {
    public final com.onetrust.otpublishers.headless.databinding.e a;
    public final com.onetrust.otpublishers.headless.UI.DataModels.i b;
    public final OTConfiguration c;
    public final String d;
    public final String e;
    public final String f;
    public final C0981a g;
    public final androidx.credentials.playservices.controllers.BeginSignIn.c h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(com.onetrust.otpublishers.headless.databinding.e binding, com.onetrust.otpublishers.headless.UI.DataModels.i sdkListData, OTConfiguration oTConfiguration, String str, String str2, String str3, C0981a onItemCheckedChange, androidx.credentials.playservices.controllers.BeginSignIn.c isAlwaysActiveGroup) {
        super((RelativeLayout) binding.b);
        Intrinsics.checkNotNullParameter(binding, "binding");
        Intrinsics.checkNotNullParameter(sdkListData, "sdkListData");
        Intrinsics.checkNotNullParameter(onItemCheckedChange, "onItemCheckedChange");
        Intrinsics.checkNotNullParameter(isAlwaysActiveGroup, "isAlwaysActiveGroup");
        this.a = binding;
        this.b = sdkListData;
        this.c = oTConfiguration;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.g = onItemCheckedChange;
        this.h = isAlwaysActiveGroup;
    }
}

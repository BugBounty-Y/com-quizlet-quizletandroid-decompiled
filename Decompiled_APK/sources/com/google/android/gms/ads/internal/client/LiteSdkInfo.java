package com.google.android.gms.ads.internal.client;

import android.content.Context;
import androidx.annotation.NonNull;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public class LiteSdkInfo extends X {
    public LiteSdkInfo(@NonNull Context context) {
        super("com.google.android.gms.ads.internal.client.ILiteSdkInfo");
    }

    @Override // com.google.android.gms.ads.internal.client.Y
    public InterfaceC2825xa getAdapterCreator() {
        return new BinderC2739va();
    }

    @Override // com.google.android.gms.ads.internal.client.Y
    public zzex getLiteSdkVersion() {
        return new zzex(ModuleDescriptor.MODULE_VERSION, ModuleDescriptor.MODULE_VERSION, "24.3.0");
    }
}

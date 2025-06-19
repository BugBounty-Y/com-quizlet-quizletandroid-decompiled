package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException;
import androidx.lifecycle.InterfaceC1261w;
import com.quizlet.studiablemodels.StudiableAudio;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D6 {
    public static final Exception a(androidx.credentials.exceptions.domerrors.a aVar, String str, GetPublicKeyCredentialDomException getPublicKeyCredentialDomException) {
        return new GetPublicKeyCredentialDomException(aVar, str);
    }

    public static final androidx.lifecycle.A0 f(androidx.lifecycle.C0 owner, com.onetrust.otpublishers.headless.UI.viewmodel.c factory) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        if (factory != null) {
            Intrinsics.checkNotNullParameter(owner, "owner");
            Intrinsics.checkNotNullParameter(factory, "factory");
            androidx.lifecycle.B0 viewModelStore = owner.getViewModelStore();
            Intrinsics.checkNotNullParameter(owner, "owner");
            return new androidx.lifecycle.A0(viewModelStore, factory, owner instanceof InterfaceC1261w ? ((InterfaceC1261w) owner).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b);
        }
        Intrinsics.checkNotNullParameter(owner, "owner");
        androidx.lifecycle.B0 viewModelStore2 = owner.getViewModelStore();
        Intrinsics.checkNotNullParameter(owner, "owner");
        boolean z = owner instanceof InterfaceC1261w;
        androidx.lifecycle.y0 defaultViewModelProviderFactory = z ? ((InterfaceC1261w) owner).getDefaultViewModelProviderFactory() : androidx.lifecycle.viewmodel.internal.b.a;
        Intrinsics.checkNotNullParameter(owner, "owner");
        return new androidx.lifecycle.A0(viewModelStore2, defaultViewModelProviderFactory, z ? ((InterfaceC1261w) owner).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b);
    }

    public static final androidx.lifecycle.w0 g(androidx.fragment.app.I i, Class clazz) {
        Intrinsics.checkNotNullParameter(i, "<this>");
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Intrinsics.checkNotNullParameter(i, "<this>");
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        return f(i, null).a(clazz);
    }

    public abstract StudiableAudio b();

    public abstract boolean c();

    public abstract boolean d();

    public abstract boolean e();
}

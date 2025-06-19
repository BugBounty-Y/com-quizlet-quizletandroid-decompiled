package com.google.firebase.crashlytics.ktx;

import androidx.annotation.Keep;
import com.google.firebase.components.ComponentRegistrar;
import java.util.List;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.collections.K;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
@InterfaceC4935d
/* loaded from: classes2.dex */
public final class FirebaseCrashlyticsKtxRegistrar implements ComponentRegistrar {

    @NotNull
    public static final a Companion = new a();

    @Override // com.google.firebase.components.ComponentRegistrar
    @NotNull
    public List<com.google.firebase.components.a> getComponents() {
        return K.a;
    }
}

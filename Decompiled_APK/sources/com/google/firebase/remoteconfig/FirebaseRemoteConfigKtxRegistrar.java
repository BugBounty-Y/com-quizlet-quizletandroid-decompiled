package com.google.firebase.remoteconfig;

import androidx.annotation.Keep;
import com.google.firebase.components.ComponentRegistrar;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class FirebaseRemoteConfigKtxRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    @NotNull
    public List<com.google.firebase.components.a> getComponents() {
        return K.a;
    }
}

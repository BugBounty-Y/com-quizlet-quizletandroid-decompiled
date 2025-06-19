package com.google.firebase.ktx;

import androidx.annotation.Keep;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3700q;
import com.google.firebase.components.ComponentRegistrar;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.A;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class FirebaseCommonLegacyRegistrar implements ComponentRegistrar {
    @Override // com.google.firebase.components.ComponentRegistrar
    @NotNull
    public List<com.google.firebase.components.a> getComponents() {
        return A.b(AbstractC3700q.a("fire-core-ktx", "21.0.0"));
    }
}

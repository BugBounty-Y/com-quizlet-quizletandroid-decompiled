package com.quizlet.shared.models.folders;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BaseFolder$Companion {
    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @NotNull
    public final KSerializer serializer() {
        return (KSerializer) b.b.getValue();
    }
}

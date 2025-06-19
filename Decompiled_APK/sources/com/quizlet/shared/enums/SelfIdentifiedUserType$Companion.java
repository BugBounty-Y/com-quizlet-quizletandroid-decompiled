package com.quizlet.shared.enums;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SelfIdentifiedUserType$Companion {
    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @NotNull
    public final KSerializer serializer() {
        return (KSerializer) j.b.getValue();
    }
}

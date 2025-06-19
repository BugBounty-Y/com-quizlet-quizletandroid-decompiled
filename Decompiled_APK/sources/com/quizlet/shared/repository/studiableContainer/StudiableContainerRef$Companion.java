package com.quizlet.shared.repository.studiableContainer;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableContainerRef$Companion {
    public static final /* synthetic */ StudiableContainerRef$Companion a = new StudiableContainerRef$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("com.quizlet.shared.repository.studiableContainer.StudiableContainerRef", K.a(a.class), new c[]{K.a(DirectStudiableContainerRef.class), K.a(IndirectStudiableContainerRef.class)}, new KSerializer[]{DirectStudiableContainerRef$$serializer.INSTANCE, IndirectStudiableContainerRef$$serializer.INSTANCE}, new Annotation[0]);
    }
}

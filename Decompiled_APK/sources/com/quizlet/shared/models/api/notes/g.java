package com.quizlet.shared.models.api.notes;

import java.lang.annotation.Annotation;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public final class g extends r implements Function0 {
    public static final g a = new g(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return new kotlinx.serialization.e("com.quizlet.shared.models.api.notes.StudyNotesRequest", K.a(h.class), new kotlin.reflect.c[0], new KSerializer[0], new Annotation[0]);
    }
}

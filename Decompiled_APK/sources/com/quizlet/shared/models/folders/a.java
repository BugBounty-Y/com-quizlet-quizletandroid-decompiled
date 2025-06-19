package com.quizlet.shared.models.folders;

import java.lang.annotation.Annotation;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public static final a a = new a(0);

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return new e("BaseFolder", K.a(b.class), new c[]{K.a(DeletedFolder.class), K.a(Folder.class)}, new KSerializer[]{DeletedFolder$$serializer.INSTANCE, Folder$$serializer.INSTANCE}, new Annotation[0]);
    }
}

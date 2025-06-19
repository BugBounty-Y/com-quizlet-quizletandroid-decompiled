package com.quizlet.data.interactor.studiablemetadata;

import assistantMode.enums.s;
import com.quizlet.shared.usecase.studiableMetadata.g;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public static final List c = B.j(s.b, s.c, s.d, s.e, s.f);
    public final g a;
    public final org.slf4j.b b;

    public b(g getStudiableMetadataUseCase, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(getStudiableMetadataUseCase, "getStudiableMetadataUseCase");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = getStudiableMetadataUseCase;
        this.b = logger;
    }
}

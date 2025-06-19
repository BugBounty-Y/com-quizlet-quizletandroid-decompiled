package com.quizlet.shared.persistence.db;

import androidx.compose.animation.core.J0;
import assistantMode.enums.s;
import assistantMode.refactored.enums.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends J0 {
    public final long c;
    public final j d;
    public final s e;
    public final /* synthetic */ g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(g gVar, long j, s studiableMetadataType, f mapper) {
        super(mapper);
        j studiableContainerType = j.b;
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.f = gVar;
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.c = j;
        this.d = studiableContainerType;
        this.e = studiableMetadataType;
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "DbStudiableMetadata.sq:select";
    }
}

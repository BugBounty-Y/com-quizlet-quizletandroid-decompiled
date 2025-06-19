package com.quizlet.shared.persistence.db;

import androidx.compose.animation.core.J0;
import assistantMode.enums.s;
import assistantMode.refactored.enums.j;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends J0 {
    public final List c;
    public final long d;
    public final j e;
    public final s f;
    public final /* synthetic */ g g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, List list, long j, s studiableMetadataType, f mapper) {
        super(mapper);
        j studiableContainerType = j.b;
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.g = gVar;
        this.c = list;
        this.d = j;
        this.e = studiableContainerType;
        this.f = studiableMetadataType;
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "DbStudiableMetadata.sq:upsert";
    }
}

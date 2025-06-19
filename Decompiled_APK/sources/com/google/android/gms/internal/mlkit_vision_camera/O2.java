package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.types.C1460g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.AztecOrderedListSpan;
import org.wordpress.aztec.spans.AztecOrderedListSpanAligned;

/* loaded from: classes2.dex */
public abstract class O2 {
    public static final /* synthetic */ int a = 0;

    public static final AztecOrderedListSpan a(int i, EnumC5145a alignmentRendering, C5146b attributes, org.wordpress.aztec.formatting.e listStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new AztecOrderedListSpan(i, attributes, listStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        AztecOrderedListSpanAligned aztecOrderedListSpanAligned = new AztecOrderedListSpanAligned(i, attributes, listStyle);
        aztecOrderedListSpanAligned.k = null;
        return aztecOrderedListSpanAligned;
    }

    public static final Q2 b(assistantMode.enums.k questionType, assistantMode.types.p questionConfig, assistantMode.utils.h studyableMaterialDataSource, boolean z) {
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        switch (questionType.ordinal()) {
            case 0:
                return new assistantMode.questions.generators.l((assistantMode.types.B) questionConfig, studyableMaterialDataSource, 1);
            case 1:
                return new assistantMode.questions.generators.k((assistantMode.types.n) questionConfig);
            case 2:
                return questionConfig instanceof C1460g ? new assistantMode.questions.generators.e((C1460g) questionConfig) : new assistantMode.questions.generators.d((assistantMode.types.B) questionConfig, studyableMaterialDataSource, z);
            case 3:
                return new assistantMode.questions.generators.f((assistantMode.types.B) questionConfig, studyableMaterialDataSource);
            case 4:
            case 8:
                return new assistantMode.questions.generators.i((assistantMode.types.B) questionConfig, questionType, studyableMaterialDataSource);
            case 5:
            case 6:
                throw new IllegalArgumentException("Unsupported question type: " + questionType);
            case 7:
                return new assistantMode.questions.generators.l((assistantMode.types.B) questionConfig, studyableMaterialDataSource, 0);
            case 9:
                return new assistantMode.questions.generators.h((assistantMode.types.n) questionConfig);
            case 10:
                return new assistantMode.questions.generators.h((assistantMode.types.j) questionConfig, studyableMaterialDataSource);
            case 11:
                return new assistantMode.questions.generators.j((assistantMode.types.o) questionConfig, studyableMaterialDataSource);
            case 12:
                return new assistantMode.questions.generators.f((assistantMode.types.i) questionConfig, studyableMaterialDataSource);
            default:
                throw new NoWhenBranchMatchedException();
        }
    }
}

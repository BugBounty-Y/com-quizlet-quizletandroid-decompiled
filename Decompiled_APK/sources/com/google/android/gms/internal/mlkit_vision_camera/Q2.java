package com.google.android.gms.internal.mlkit_vision_camera;

import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5168p;
import org.wordpress.aztec.spans.C5169q;

/* loaded from: classes2.dex */
public abstract class Q2 {
    public static final C5168p a(int i, C5146b attributes, EnumC5145a alignmentRendering, org.wordpress.aztec.formatting.h quoteStyle) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(quoteStyle, "quoteStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new C5168p(i, attributes, quoteStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(quoteStyle, "quoteStyle");
        C5169q c5169q = new C5169q(i, attributes, quoteStyle);
        c5169q.o = null;
        return c5169q;
    }

    public int b() {
        return 1;
    }

    public abstract assistantMode.grading.d c();

    public abstract assistantMode.refactored.types.d d();

    public abstract List e();
}

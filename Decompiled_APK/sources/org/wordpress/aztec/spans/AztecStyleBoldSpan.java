package org.wordpress.aztec.spans;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecStyleBoldSpan extends AztecStyleSpan {
    public /* synthetic */ AztecStyleBoldSpan() {
        this(new C5146b());
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecStyleBoldSpan(C5146b attributes) {
        super(1, attributes);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
    }
}

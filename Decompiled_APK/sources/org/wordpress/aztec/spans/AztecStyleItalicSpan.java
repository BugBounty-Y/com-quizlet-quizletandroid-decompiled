package org.wordpress.aztec.spans;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecStyleItalicSpan extends AztecStyleSpan {
    public /* synthetic */ AztecStyleItalicSpan() {
        this(new C5146b());
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecStyleItalicSpan(C5146b attributes) {
        super(2, attributes);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
    }
}

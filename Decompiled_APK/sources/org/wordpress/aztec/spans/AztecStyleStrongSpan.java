package org.wordpress.aztec.spans;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecStyleStrongSpan extends AztecStyleSpan {
    public final kotlin.u c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecStyleStrongSpan(C5146b attributes) {
        super(1, attributes);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.c = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.match.fragment.t(this, 21));
    }

    @Override // org.wordpress.aztec.spans.AztecStyleSpan, org.wordpress.aztec.spans.M
    public final String u() {
        return (String) this.c.getValue();
    }
}

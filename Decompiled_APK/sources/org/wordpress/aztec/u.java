package org.wordpress.aztec;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.AztecTaskListSpan;

/* loaded from: classes3.dex */
public final class u extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AztecText b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ u(AztecText aztecText, int i) {
        super(1);
        this.a = i;
        this.b = aztecText;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AztecTaskListSpan it2 = (AztecTaskListSpan) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                AztecText.c(this.b, it2);
                break;
            default:
                AztecTaskListSpan it3 = (AztecTaskListSpan) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                AztecText.c(this.b, it3);
                break;
        }
        return Unit.a;
    }
}

package kotlin.sequences;

import androidx.core.view.C;
import java.util.Iterator;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements Sequence {
    public final /* synthetic */ int a;
    public final Sequence b;
    public final Function1 c;

    public t(Sequence sequence, Function1 transformer, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                Intrinsics.checkNotNullParameter(transformer, "transformer");
                this.b = sequence;
                this.c = transformer;
                break;
            default:
                Intrinsics.checkNotNullParameter(sequence, "sequence");
                Intrinsics.checkNotNullParameter(transformer, "predicate");
                this.b = sequence;
                this.c = transformer;
                break;
        }
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new e(this);
            default:
                return new C(this);
        }
    }
}

package kotlin.sequences;

import java.util.Iterator;
import kotlin.collections.O;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements Sequence, c {
    public final Sequence a;

    public s(Sequence sequence) {
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        this.a = sequence;
    }

    @Override // kotlin.sequences.c
    public final Sequence a(int i) {
        return i >= 7 ? d.a : new r(this.a, i, 7);
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return new O(this);
    }

    @Override // kotlin.sequences.c
    public final Sequence take() {
        return this;
    }
}

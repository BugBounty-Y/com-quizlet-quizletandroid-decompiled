package kotlin.sequences;

import java.util.Iterator;
import kotlin.collections.J;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d implements Sequence, c {

    @NotNull
    public static final d a = new d();

    @Override // kotlin.sequences.c
    public final Sequence a(int i) {
        return a;
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return J.a;
    }

    @Override // kotlin.sequences.c
    public final Sequence take() {
        return a;
    }
}

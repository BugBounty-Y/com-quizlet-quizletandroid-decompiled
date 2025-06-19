package kotlin.text;

import java.util.Iterator;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;

/* renamed from: kotlin.text.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4964c implements Sequence {
    public final CharSequence a;
    public final int b;
    public final kotlin.jvm.internal.r c;

    /* JADX WARN: Multi-variable type inference failed */
    public C4964c(CharSequence input, int i, Function2 getNextMatch) {
        Intrinsics.checkNotNullParameter(input, "input");
        Intrinsics.checkNotNullParameter(getNextMatch, "getNextMatch");
        this.a = input;
        this.b = i;
        this.c = (kotlin.jvm.internal.r) getNextMatch;
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return new C4963b(this);
    }
}

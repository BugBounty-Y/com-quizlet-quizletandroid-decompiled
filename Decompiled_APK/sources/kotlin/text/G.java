package kotlin.text;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes3.dex */
public final class G extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ CharSequence a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(CharSequence charSequence) {
        super(1);
        this.a = charSequence;
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final String invoke(IntRange it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        return StringsKt.Y(this.a, it2);
    }
}

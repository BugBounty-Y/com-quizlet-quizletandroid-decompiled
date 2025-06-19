package kotlin.sequences;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class p extends kotlin.jvm.internal.r implements Function1 {
    public static final p a = new p(1);

    public p() {
        super(1);
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final Boolean invoke(Object obj) {
        return Boolean.valueOf(obj == null);
    }
}

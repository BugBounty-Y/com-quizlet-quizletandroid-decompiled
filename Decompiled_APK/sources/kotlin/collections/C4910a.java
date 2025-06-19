package kotlin.collections;

import kotlin.jvm.functions.Function1;

/* renamed from: kotlin.collections.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4910a extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ AbstractC4911b a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4910a(AbstractC4911b abstractC4911b) {
        super(1);
        this.a = abstractC4911b;
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final CharSequence invoke(Object obj) {
        return obj == this.a ? "(this Collection)" : String.valueOf(obj);
    }
}

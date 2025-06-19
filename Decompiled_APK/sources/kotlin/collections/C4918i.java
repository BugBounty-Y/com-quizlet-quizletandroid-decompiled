package kotlin.collections;

import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlin.collections.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4918i extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ AbstractC4919j a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4918i(AbstractC4919j abstractC4919j) {
        super(1);
        this.a = abstractC4919j;
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final CharSequence invoke(Map.Entry<Object, Object> it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        C4917h c4917h = AbstractC4919j.a;
        AbstractC4919j abstractC4919j = this.a;
        StringBuilder sb = new StringBuilder();
        Object key = it2.getKey();
        sb.append(key == abstractC4919j ? "(this Map)" : String.valueOf(key));
        sb.append('=');
        Object value = it2.getValue();
        sb.append(value != abstractC4919j ? String.valueOf(value) : "(this Map)");
        return sb.toString();
    }
}

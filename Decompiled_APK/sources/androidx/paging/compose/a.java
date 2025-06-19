package androidx.paging.compose;

import androidx.compose.runtime.L0;
import androidx.paging.A;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public final /* synthetic */ Function1 a;
    public final /* synthetic */ d b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(d dVar, Function1 function1) {
        super(1);
        this.a = function1;
        this.b = dVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int iIntValue = ((Number) obj).intValue();
        Function1 function1 = this.a;
        Object obj2 = ((A) ((L0) this.b.d).getValue()).get(iIntValue);
        return obj2 == null ? new PagingPlaceholderKey(iIntValue) : function1.invoke(obj2);
    }
}

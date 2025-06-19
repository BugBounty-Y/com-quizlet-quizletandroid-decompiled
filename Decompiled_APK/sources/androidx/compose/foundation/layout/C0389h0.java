package androidx.compose.foundation.layout;

import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.layout.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0389h0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.layout.f0 b;
    public final /* synthetic */ C0391i0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0389h0(C0391i0 c0391i0, androidx.compose.ui.layout.f0 f0Var) {
        super(2);
        this.c = c0391i0;
        this.b = f0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                int iIntValue = ((Number) obj2).intValue();
                int i = !zBooleanValue ? 1 : 0;
                C0391i0 c0391i0 = this.c;
                Function2 function2 = (Function2) CollectionsKt.O(i, c0391i0.h);
                if (function2 == null) {
                    return null;
                }
                StringBuilder sb = new StringBuilder();
                sb.append(zBooleanValue);
                sb.append(c0391i0.f);
                sb.append(iIntValue);
                return (androidx.compose.ui.layout.J) CollectionsKt.O(0, this.b.n(sb.toString(), function2));
            default:
                int iIntValue2 = ((Number) obj).intValue();
                return this.b.n(Integer.valueOf(iIntValue2), new androidx.compose.runtime.internal.d(true, -195060736, new androidx.compose.animation.core.D0(this.c, iIntValue2, (C0383e0) obj2, 1)));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0389h0(androidx.compose.ui.layout.f0 f0Var, C0391i0 c0391i0) {
        super(2);
        this.b = f0Var;
        this.c = c0391i0;
    }
}

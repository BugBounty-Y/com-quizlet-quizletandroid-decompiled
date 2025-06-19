package androidx.compose.foundation.pager;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.pager.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0465d extends kotlin.jvm.internal.r implements Function1 {
    public static final C0465d b = new C0465d(1, 0);
    public static final C0465d c = new C0465d(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0465d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Object obj2 = list.get(0);
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Int");
                int iIntValue = ((Integer) obj2).intValue();
                Object obj3 = list.get(1);
                Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Float");
                return new C0466e(iIntValue, ((Float) obj3).floatValue(), new C0464c(list, 0));
            default:
                return Unit.a;
        }
    }
}

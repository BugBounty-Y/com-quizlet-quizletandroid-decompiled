package androidx.compose.ui.text.input;

import androidx.compose.ui.text.C0995g;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.input.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1001d extends kotlin.jvm.internal.r implements Function1 {
    public static final C1001d b = new C1001d(1, 0);
    public static final C1001d c = new C1001d(1, 1);
    public static final C1001d d = new C1001d(1, 2);
    public static final C1001d e = new C1001d(1, 3);
    public static final C1001d f = new C1001d(1, 4);
    public static final C1001d g = new C1001d(1, 5);
    public static final C1001d h = new C1001d(1, 6);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1001d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                float[] fArr = ((androidx.compose.ui.graphics.J) obj).a;
                break;
            case 1:
                float[] fArr2 = ((androidx.compose.ui.graphics.J) obj).a;
                break;
            case 2:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list = (List) obj;
                Object obj2 = list.get(0);
                com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.ui.text.C.a;
                Boolean bool = Boolean.FALSE;
                C0995g c0995g = (Intrinsics.b(obj2, bool) || obj2 == null) ? null : (C0995g) ((Function1) aVar.c).invoke(obj2);
                Intrinsics.d(c0995g);
                Object obj3 = list.get(1);
                int i = androidx.compose.ui.text.K.c;
                androidx.compose.ui.text.K k = (Intrinsics.b(obj3, bool) || obj3 == null) ? null : (androidx.compose.ui.text.K) ((Function1) androidx.compose.ui.text.C.p.c).invoke(obj3);
                Intrinsics.d(k);
                break;
            case 3:
                break;
            case 4:
                int i2 = ((l) obj).a;
                break;
            case 5:
                break;
            default:
                int i3 = ((l) obj).a;
                break;
        }
        return Unit.a;
    }
}

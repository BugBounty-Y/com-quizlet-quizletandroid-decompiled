package androidx.glance.text;

import androidx.glance.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class e extends r implements Function2 {
    public static final e b = new e(2, 0);
    public static final e c = new e(2, 1);
    public static final e d = new e(2, 2);
    public static final e e = new e(2, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((a) obj).a = (String) obj2;
                break;
            case 1:
                ((a) obj).d = (p) obj2;
                break;
            case 2:
                ((a) obj).b = (g) obj2;
                break;
            default:
                ((a) obj).c = ((Number) obj2).intValue();
                break;
        }
        return Unit.a;
    }
}

package androidx.glance.appwidget.lazy;

import androidx.glance.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function2 {
    public static final d b = new d(2, 0);
    public static final d c = new d(2, 1);
    public static final d d = new d(2, 2);
    public static final d e = new d(2, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((a) obj).d = (p) obj2;
                break;
            case 1:
                ((a) obj).e = ((androidx.glance.layout.a) obj2).a;
                break;
            case 2:
                ((b) obj).f = ((Number) obj2).longValue();
                break;
            default:
                ((b) obj).d = (androidx.glance.layout.c) obj2;
                break;
        }
        return Unit.a;
    }
}

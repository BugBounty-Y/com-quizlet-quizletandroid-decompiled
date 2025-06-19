package androidx.glance;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class g extends kotlin.jvm.internal.r implements Function2 {
    public static final g b = new g(2, 0);
    public static final g c = new g(2, 1);
    public static final g d = new g(2, 2);
    public static final g e = new g(2, 3);
    public static final g f = new g(2, 4);
    public static final g g = new g(2, 5);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                String str = (String) obj;
                o oVar = (o) obj2;
                if (str.length() == 0) {
                    return oVar.toString();
                }
                return str + ", " + oVar;
            case 1:
                ((l) obj).b = (a) obj2;
                return Unit.a;
            case 2:
                ((l) obj).a = (p) obj2;
                return Unit.a;
            case 3:
                ((androidx.glance.layout.h) obj2).getClass();
                ((l) obj).d = 1;
                return Unit.a;
            case 4:
                f fVar = (f) obj2;
                ((l) obj).c = fVar != null ? fVar.a : null;
                return Unit.a;
            default:
                o oVar2 = (o) obj2;
                return oVar2 instanceof androidx.glance.semantics.b ? oVar2 : obj;
        }
    }
}

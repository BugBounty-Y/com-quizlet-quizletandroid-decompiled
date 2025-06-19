package androidx.compose.ui.focus;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class i extends kotlin.jvm.internal.r implements Function1 {
    public static final i b = new i(1, 0);
    public static final i c = new i(1, 1);
    public static final i d = new i(1, 2);
    public static final i e = new i(1, 3);
    public static final i f = new i(1, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((k) obj).d(false);
                return Unit.a;
            case 1:
                int i = ((c) obj).a;
                return p.b;
            case 2:
                int i2 = ((c) obj).a;
                return p.b;
            case 3:
                Boolean boolF = a.F((t) obj, 7);
                return Boolean.valueOf(boolF != null ? boolF.booleanValue() : false);
            default:
                Boolean boolF2 = a.F((t) obj, 7);
                return Boolean.valueOf(boolF2 != null ? boolF2.booleanValue() : false);
        }
    }
}

package androidx.glance.layout;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class e extends kotlin.jvm.internal.r implements Function2 {
    public static final e b = new e(2, 0);
    public static final e c = new e(2, 1);
    public static final e d = new e(2, 2);
    public static final e e = new e(2, 3);
    public static final e f = new e(2, 4);
    public static final e g = new e(2, 5);
    public static final e h = new e(2, 6);
    public static final e i = new e(2, 7);
    public static final e j = new e(2, 8);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((i) obj).d = (androidx.glance.p) obj2;
                break;
            case 1:
                ((i) obj).e = (c) obj2;
                break;
            case 2:
                ((j) obj).d = (androidx.glance.p) obj2;
                break;
            case 3:
                ((j) obj).f = ((a) obj2).a;
                break;
            case 4:
                ((j) obj).e = ((b) obj2).a;
                break;
            case 5:
                ((k) obj).d = (androidx.glance.p) obj2;
                break;
            case 6:
                ((k) obj).f = ((b) obj2).a;
                break;
            case 7:
                ((k) obj).e = ((a) obj2).a;
                break;
            default:
                ((l) obj).a = (androidx.glance.p) obj2;
                break;
        }
        return Unit.a;
    }
}

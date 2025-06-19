package androidx.compose.material3;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0736u extends kotlin.jvm.internal.r implements Function1 {
    public static final C0736u b = new C0736u(1, 0);
    public static final C0736u c = new C0736u(1, 1);
    public static final C0736u d = new C0736u(1, 2);
    public static final C0736u e = new C0736u(1, 3);
    public static final C0736u f = new C0736u(1, 4);
    public static final C0736u g = new C0736u(1, 5);
    public static final C0736u h = new C0736u(1, 6);
    public static final C0736u i = new C0736u(1, 7);
    public static final C0736u j = new C0736u(1, 8);
    public static final C0736u k = new C0736u(1, 9);
    public static final C0736u l = new C0736u(1, 10);
    public static final C0736u m = new C0736u(1, 11);
    public static final C0736u n = new C0736u(1, 12);
    public static final C0736u o = new C0736u(1, 13);
    public static final C0736u p = new C0736u(1, 14);
    public static final C0736u q = new C0736u(1, 15);
    public static final C0736u r = new C0736u(1, 16);
    public static final C0736u s = new C0736u(1, 17);
    public static final C0736u t = new C0736u(1, 18);
    public static final C0736u u = new C0736u(1, 19);
    public static final C0736u v = new C0736u(1, 20);
    public static final C0736u w = new C0736u(1, 21);
    public static final C0736u x = new C0736u(1, 22);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0736u(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                androidx.compose.ui.semantics.t.h((androidx.compose.ui.semantics.v) obj, 0);
                return Unit.a;
            case 2:
                return Unit.a;
            case 3:
                androidx.compose.ui.semantics.t.d((androidx.compose.ui.semantics.v) obj);
                return Unit.a;
            case 4:
                androidx.compose.ui.semantics.i iVar = new androidx.compose.ui.semantics.i(C0584a0.g, C0584a0.h);
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.o;
                kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[10];
                uVar.a((androidx.compose.ui.semantics.v) obj, iVar);
                return Unit.a;
            case 5:
                return Unit.a;
            case 6:
                androidx.compose.ui.semantics.t.d((androidx.compose.ui.semantics.v) obj);
                return Unit.a;
            case 7:
                return Integer.valueOf(((Number) obj).intValue());
            case 8:
                return Integer.valueOf(((Number) obj).intValue());
            case 9:
                androidx.compose.ui.semantics.i iVar2 = new androidx.compose.ui.semantics.i(C0584a0.i, C0584a0.j);
                kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.p;
                kotlin.reflect.n nVar2 = androidx.compose.ui.semantics.t.a[11];
                uVar2.a((androidx.compose.ui.semantics.v) obj, iVar2);
                return Unit.a;
            case 10:
                return Unit.a;
            case 11:
                androidx.compose.ui.semantics.t.h((androidx.compose.ui.semantics.v) obj, 0);
                return Unit.a;
            case 12:
                androidx.compose.ui.semantics.t.h((androidx.compose.ui.semantics.v) obj, 1);
                return Unit.a;
            case 13:
                return Unit.a;
            case 14:
                androidx.compose.ui.semantics.t.k((androidx.compose.ui.semantics.v) obj);
                return Unit.a;
            case 15:
                return Boolean.TRUE;
            case 16:
                kotlin.reflect.n[] nVarArr3 = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.r;
                Unit unit = Unit.a;
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(uVar3, unit);
                return unit;
            case 17:
                return Unit.a;
            case 18:
                return Unit.a;
            case 19:
                return Unit.a;
            case 20:
                androidx.compose.ui.semantics.t.d((androidx.compose.ui.semantics.v) obj);
                return Unit.a;
            case 21:
                return Unit.a;
            default:
                List list = (List) obj;
                return new X4(((Number) list.get(0)).floatValue(), ((Number) list.get(1)).floatValue(), ((Number) list.get(2)).floatValue());
        }
    }
}

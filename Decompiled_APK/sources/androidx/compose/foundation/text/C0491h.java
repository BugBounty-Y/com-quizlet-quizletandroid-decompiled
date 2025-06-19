package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.text.input.C1004g;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0491h extends kotlin.jvm.internal.r implements Function1 {
    public static final C0491h b = new C0491h(1, 0);
    public static final C0491h c = new C0491h(1, 1);
    public static final C0491h d = new C0491h(1, 2);
    public static final C0491h e = new C0491h(1, 3);
    public static final C0491h f = new C0491h(1, 4);
    public static final C0491h g = new C0491h(1, 5);
    public static final C0491h h = new C0491h(1, 6);
    public static final C0491h i = new C0491h(1, 7);
    public static final C0491h j = new C0491h(1, 8);
    public static final C0491h k = new C0491h(1, 9);
    public static final C0491h l = new C0491h(1, 10);
    public static final C0491h m = new C0491h(1, 11);
    public static final C0491h n = new C0491h(1, 12);
    public static final C0491h o = new C0491h(1, 13);
    public static final C0491h p = new C0491h(1, 14);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0491h(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Integer numValueOf;
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                return Unit.a;
            case 2:
                return Long.valueOf(((Number) obj).longValue());
            case 3:
                return Unit.a;
            case 4:
                return Unit.a;
            case 5:
                return Unit.a;
            case 6:
                return Unit.a;
            case 7:
                androidx.compose.foundation.text.selection.g0 g0Var = (androidx.compose.foundation.text.selection.g0) obj;
                long j2 = g0Var.f;
                int i2 = androidx.compose.ui.text.K.c;
                return new C1004g(((int) (j2 & 4294967295L)) - AbstractC0484d0.v((int) (4294967295L & j2), g0Var.g.a), 0);
            case 8:
                androidx.compose.foundation.text.selection.g0 g0Var2 = (androidx.compose.foundation.text.selection.g0) obj;
                String str = g0Var2.g.a;
                long j3 = g0Var2.f;
                int i3 = androidx.compose.ui.text.K.c;
                int iS = AbstractC0484d0.s((int) (j3 & 4294967295L), str);
                if (iS != -1) {
                    return new C1004g(0, iS - ((int) (4294967295L & g0Var2.f)));
                }
                return null;
            case 9:
                androidx.compose.foundation.text.selection.g0 g0Var3 = (androidx.compose.foundation.text.selection.g0) obj;
                Integer numD = g0Var3.d();
                if (numD == null) {
                    return null;
                }
                int iIntValue = numD.intValue();
                long j4 = g0Var3.f;
                int i4 = androidx.compose.ui.text.K.c;
                return new C1004g(((int) (4294967295L & j4)) - iIntValue, 0);
            case 10:
                androidx.compose.foundation.text.selection.g0 g0Var4 = (androidx.compose.foundation.text.selection.g0) obj;
                Integer numC = g0Var4.c();
                if (numC == null) {
                    return null;
                }
                int iIntValue2 = numC.intValue();
                long j5 = g0Var4.f;
                int i5 = androidx.compose.ui.text.K.c;
                return new C1004g(0, iIntValue2 - ((int) (4294967295L & j5)));
            case 11:
                androidx.compose.foundation.text.selection.g0 g0Var5 = (androidx.compose.foundation.text.selection.g0) obj;
                androidx.compose.ui.text.H h2 = g0Var5.c;
                if (h2 != null) {
                    int iE = androidx.compose.ui.text.K.e(g0Var5.f);
                    androidx.compose.ui.text.input.s sVar = g0Var5.d;
                    numValueOf = Integer.valueOf(sVar.g(h2.i(h2.f(sVar.p(iE)))));
                } else {
                    numValueOf = null;
                }
                if (numValueOf == null) {
                    return null;
                }
                int iIntValue3 = numValueOf.intValue();
                long j6 = g0Var5.f;
                int i6 = androidx.compose.ui.text.K.c;
                return new C1004g(((int) (4294967295L & j6)) - iIntValue3, 0);
            case 12:
                androidx.compose.foundation.text.selection.g0 g0Var6 = (androidx.compose.foundation.text.selection.g0) obj;
                Integer numB = g0Var6.b();
                if (numB == null) {
                    return null;
                }
                int iIntValue4 = numB.intValue();
                long j7 = g0Var6.f;
                int i7 = androidx.compose.ui.text.K.c;
                return new C1004g(0, iIntValue4 - ((int) (4294967295L & j7)));
            case 13:
                List list = (List) obj;
                Object obj2 = list.get(1);
                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Boolean");
                EnumC0320d0 enumC0320d0 = ((Boolean) obj2).booleanValue() ? EnumC0320d0.a : EnumC0320d0.b;
                Object obj3 = list.get(0);
                Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.Float");
                return new I0(enumC0320d0, ((Float) obj3).floatValue());
            default:
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.m;
                Unit unit = Unit.a;
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(uVar, unit);
                return unit;
        }
    }
}

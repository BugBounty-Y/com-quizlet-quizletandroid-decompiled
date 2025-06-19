package androidx.glance.appwidget;

import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.t7;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class q0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public static final q0 b = new q0(2, 0);
    public static final q0 c = new q0(2, 1);
    public static final q0 d = new q0(2, 2);
    public static final q0 e = new q0(2, 3);
    public static final q0 f = new q0(2, 4);
    public static final q0 g = new q0(2, 5);
    public static final q0 h = new q0(2, 6);
    public static final q0 i = new q0(2, 7);
    public static final q0 j = new q0(2, 8);
    public static final q0 k = new q0(2, 9);
    public static final q0 l = new q0(2, 10);
    public static final q0 m = new q0(2, 11);
    public static final q0 n = new q0(2, 12);
    public static final q0 o = new q0(2, 13);
    public static final q0 p = new q0(2, 14);
    public static final q0 q = new q0(2, 15);
    public static final q0 r = new q0(2, 16);
    public static final q0 s = new q0(2, 17);
    public static final q0 t = new q0(2, 18);
    public static final q0 u = new q0(2, 19);
    public static final q0 v = new q0(2, 20);
    public static final q0 w = new q0(2, 21);
    public static final q0 x = new q0(2, 22);
    public static final q0 y = new q0(2, 23);
    public static final q0 z = new q0(2, 24);
    public static final q0 A = new q0(2, 25);
    public static final q0 B = new q0(2, 26);
    public static final q0 C = new q0(2, 27);

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q0(int i2) {
        super(2);
        this.a = 28;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                androidx.glance.o oVar = (androidx.glance.o) obj2;
                return oVar instanceof androidx.glance.layout.t ? oVar : obj;
            case 1:
                androidx.glance.o oVar2 = (androidx.glance.o) obj2;
                return oVar2 instanceof androidx.glance.layout.m ? oVar2 : obj;
            case 2:
                androidx.glance.o oVar3 = (androidx.glance.o) obj2;
                return oVar3 instanceof androidx.glance.layout.t ? oVar3 : obj;
            case 3:
                androidx.glance.o oVar4 = (androidx.glance.o) obj2;
                return oVar4 instanceof androidx.glance.layout.m ? oVar4 : obj;
            case 4:
                androidx.glance.o oVar5 = (androidx.glance.o) obj2;
                return oVar5 instanceof androidx.glance.layout.t ? oVar5 : obj;
            case 5:
                androidx.glance.o oVar6 = (androidx.glance.o) obj2;
                return oVar6 instanceof androidx.glance.layout.m ? oVar6 : obj;
            case 6:
                androidx.glance.o oVar7 = (androidx.glance.o) obj2;
                return oVar7 instanceof C1158a ? oVar7 : obj;
            case 7:
                androidx.glance.o oVar8 = (androidx.glance.o) obj2;
                return oVar8 instanceof androidx.glance.layout.t ? oVar8 : obj;
            case 8:
                androidx.glance.o oVar9 = (androidx.glance.o) obj2;
                return oVar9 instanceof androidx.glance.layout.m ? oVar9 : obj;
            case 9:
                ((D) obj).a = (androidx.glance.p) obj2;
                return Unit.a;
            case 10:
                ((D) obj).b = ((Number) obj2).floatValue();
                return Unit.a;
            case 11:
                ((D) obj).c = (androidx.glance.unit.a) obj2;
                return Unit.a;
            case 12:
                ((D) obj).d = (androidx.glance.unit.a) obj2;
                return Unit.a;
            case 13:
                Pair pair = (Pair) obj;
                androidx.glance.o oVar10 = (androidx.glance.o) obj2;
                return oVar10 instanceof androidx.glance.action.b ? new Pair(oVar10, pair.b) : new Pair(pair.a, ((androidx.glance.p) pair.b).d(oVar10));
            case 14:
                G g2 = (G) obj;
                androidx.glance.o oVar11 = (androidx.glance.o) obj2;
                if ((oVar11 instanceof androidx.glance.layout.t) || (oVar11 instanceof androidx.glance.layout.m) || (oVar11 instanceof A)) {
                    return new G(g2.a.d(oVar11), g2.b);
                }
                return new G(g2.a, g2.b.d(oVar11));
            case 15:
                androidx.glance.o oVar12 = (androidx.glance.o) obj2;
                return oVar12 instanceof androidx.glance.layout.m ? oVar12 : obj;
            case 16:
                androidx.glance.o oVar13 = (androidx.glance.o) obj2;
                return oVar13 instanceof androidx.glance.layout.t ? oVar13 : obj;
            case 17:
                androidx.glance.o oVar14 = (androidx.glance.o) obj2;
                return oVar14 instanceof androidx.glance.layout.m ? oVar14 : obj;
            case 18:
                androidx.glance.o oVar15 = (androidx.glance.o) obj2;
                return oVar15 instanceof androidx.glance.layout.t ? oVar15 : obj;
            case 19:
                Pair pair2 = (Pair) obj;
                androidx.glance.o oVar16 = (androidx.glance.o) obj2;
                return oVar16 instanceof androidx.glance.e ? new Pair(oVar16, pair2.b) : new Pair(pair2.a, ((androidx.glance.p) pair2.b).d(oVar16));
            case 20:
                Pair pair3 = (Pair) obj;
                androidx.glance.o oVar17 = (androidx.glance.o) obj2;
                return oVar17 instanceof androidx.glance.action.b ? new Pair(oVar17, pair3.b) : new Pair(pair3.a, ((androidx.glance.p) pair3.b).d(oVar17));
            case 21:
                int iIntValue = ((Number) obj).intValue();
                if (((androidx.glance.o) obj2) instanceof androidx.glance.action.b) {
                    iIntValue++;
                }
                return Integer.valueOf(iIntValue);
            case EventType.WINDOW_STATE /* 22 */:
                ((E) obj).d = ((androidx.compose.ui.unit.g) obj2).a;
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                ((E) obj).e = (J0) obj2;
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                androidx.glance.o oVar18 = (androidx.glance.o) obj2;
                return oVar18 instanceof androidx.glance.action.b ? oVar18 : obj;
            case EventType.SUBS /* 25 */:
                return obj;
            case EventType.CDN /* 26 */:
                androidx.glance.o oVar19 = (androidx.glance.o) obj2;
                return oVar19 instanceof androidx.glance.layout.t ? oVar19 : obj;
            case 27:
                androidx.glance.o oVar20 = (androidx.glance.o) obj2;
                return oVar20 instanceof androidx.glance.layout.m ? oVar20 : obj;
            default:
                ((Number) obj2).intValue();
                t7.a((InterfaceC0806l) obj, 1);
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q0(int i2, int i3) {
        super(i2);
        this.a = i3;
    }
}

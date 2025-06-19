package assistantMode.learningModel;

import assistantMode.enums.k;
import assistantMode.enums.m;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final Object a;
    public static final Object b;
    public static final List c;

    static {
        k kVar = k.b;
        Double dValueOf = Double.valueOf(1.0d);
        Pair pair = new Pair(kVar, dValueOf);
        k kVar2 = k.d;
        Pair pair2 = new Pair(kVar2, Double.valueOf(2.05527348979d));
        k kVar3 = k.e;
        Pair pair3 = new Pair(kVar3, Double.valueOf(1.96165431908d));
        k kVar4 = k.f;
        Pair pair4 = new Pair(kVar4, Double.valueOf(0.765450452372d));
        k kVar5 = k.g;
        Pair pair5 = new Pair(kVar5, Double.valueOf(1.82685233786d));
        k kVar6 = k.h;
        Pair pair6 = new Pair(kVar6, Double.valueOf(6.83879309464d));
        k kVar7 = k.l;
        Pair pair7 = new Pair(kVar7, dValueOf);
        k kVar8 = k.n;
        Pair pair8 = new Pair(kVar8, Double.valueOf(2.05527348979d));
        k kVar9 = k.m;
        a = V.f(pair, pair2, pair3, pair4, pair5, pair6, pair7, pair8, new Pair(kVar9, Double.valueOf(2.05527348979d)));
        b = V.f(new Pair(kVar, Double.valueOf(0.662573556200577d)), new Pair(kVar2, Double.valueOf(0.8705655009881929d)), new Pair(kVar3, Double.valueOf(0.8777463068695633d)), new Pair(kVar4, Double.valueOf(0.7004481612133597d)), new Pair(kVar5, Double.valueOf(0.7997362050328207d)), new Pair(kVar6, Double.valueOf(0.662573556200577d)), new Pair(kVar7, Double.valueOf(0.6d)), new Pair(kVar8, Double.valueOf(0.8705655009881929d)), new Pair(kVar9, Double.valueOf(0.8705655009881929d)));
        c = B.j(kVar7, kVar);
    }

    public static final c a(Map map, m mVar) {
        Object obj = map.get(mVar);
        if (obj != null) {
            return (c) obj;
        }
        throw new IllegalStateException(("Current state is null for answer side: " + mVar).toString());
    }

    public static final double b(k kVar, Boolean bool) {
        if (c.contains(kVar)) {
            return 0.0d;
        }
        k kVar2 = k.h;
        if (kVar == kVar2 && !Intrinsics.b(bool, Boolean.TRUE)) {
            return 0.0d;
        }
        if ((kVar == kVar2 && Intrinsics.b(bool, Boolean.TRUE)) || kVar == k.f) {
            return 0.0d;
        }
        if (kVar == k.d || kVar == k.n || kVar == k.m) {
            return 0.25d;
        }
        if (kVar == k.g) {
            return 0.2d;
        }
        if (kVar == k.e) {
            return 0.5d;
        }
        throw new IllegalStateException("Cannot determine random guess correct probability for unrecognized question type: " + kVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x01bf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final assistantMode.learningModel.b c(java.util.List r28) {
        /*
            Method dump skipped, instructions count: 532
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.learningModel.a.c(java.util.List):assistantMode.learningModel.b");
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00a7  */
    /* JADX WARN: Type inference failed for: r12v0, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r9v12, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final assistantMode.learningModel.d d(double r9, double r11, assistantMode.enums.k r13, java.lang.Double r14, java.lang.Boolean r15) {
        /*
            r0 = 1
            java.lang.String r1 = "questionType"
            if (r14 != 0) goto L3e
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r1)
            java.lang.Object r9 = assistantMode.learningModel.a.b
            java.lang.Object r9 = r9.get(r13)
            if (r9 == 0) goto L26
            java.lang.Number r9 = (java.lang.Number) r9
            double r9 = r9.doubleValue()
            java.lang.Boolean r11 = java.lang.Boolean.FALSE
            double r1 = b(r13, r11)
            double r9 = r9 - r1
            double r1 = (double) r0
            double r11 = b(r13, r11)
            double r1 = r1 - r11
            double r9 = r9 / r1
            goto L99
        L26:
            java.lang.StringBuilder r9 = new java.lang.StringBuilder
            java.lang.String r10 = "Cannot determine initial answer correct probability for unrecognized question type: "
            r9.<init>(r10)
            r9.append(r13)
            java.lang.String r9 = r9.toString()
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r9 = r9.toString()
            r10.<init>(r9)
            throw r10
        L3e:
            double r2 = r14.doubleValue()
            r4 = 0
            int r2 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            r3 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            if (r2 > 0) goto L4c
        L4a:
            r9 = r3
            goto L6b
        L4c:
            double r5 = r14.doubleValue()
            r7 = -4571364728013586432(0xc08f400000000000, double:-1000.0)
            int r14 = (r9 > r7 ? 1 : (r9 == r7 ? 0 : -1))
            if (r14 >= 0) goto L5a
            goto L4a
        L5a:
            double r9 = -r9
            double r9 = java.lang.Math.exp(r9)
            double r11 = -r11
            double r11 = java.lang.Math.exp(r11)
            double r9 = r9 * r5
            double r9 = r9 + r3
            double r11 = -r11
            double r9 = java.lang.Math.pow(r9, r11)
        L6b:
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r1)
            assistantMode.enums.k r11 = assistantMode.enums.k.h
            java.lang.Object r12 = assistantMode.learningModel.a.a
            if (r13 != r11) goto L85
            java.lang.Boolean r11 = java.lang.Boolean.TRUE
            boolean r11 = kotlin.jvm.internal.Intrinsics.b(r15, r11)
            if (r11 != 0) goto L85
            assistantMode.enums.k r11 = assistantMode.enums.k.b
            java.lang.Object r11 = r12.get(r11)
            java.lang.Double r11 = (java.lang.Double) r11
            goto L8b
        L85:
            java.lang.Object r11 = r12.get(r13)
            java.lang.Double r11 = (java.lang.Double) r11
        L8b:
            if (r11 == 0) goto La7
            double r11 = r11.doubleValue()
            double r1 = r11 * r9
            double r11 = r3 - r11
            double r11 = r11 * r9
            double r3 = r3 - r11
            double r9 = r1 / r3
        L99:
            double r11 = (double) r0
            double r11 = r11 - r9
            double r13 = b(r13, r15)
            double r13 = r13 * r11
            assistantMode.learningModel.d r11 = new assistantMode.learningModel.d
            double r9 = r9 + r13
            r11.<init>(r9, r13)
            return r11
        La7:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "value is undefined"
            r9.<init>(r10)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.learningModel.a.d(double, double, assistantMode.enums.k, java.lang.Double, java.lang.Boolean):assistantMode.learningModel.d");
    }
}

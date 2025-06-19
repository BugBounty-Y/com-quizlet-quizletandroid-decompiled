package androidx.compose.ui.text;

import android.util.Log;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.U;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements Function1 {
    public static final A b = new A(1, 0);
    public static final A c = new A(1, 1);
    public static final A d = new A(1, 2);
    public static final A e = new A(1, 3);
    public static final A f = new A(1, 4);
    public static final A g = new A(1, 5);
    public static final A h = new A(1, 6);
    public static final A i = new A(1, 7);
    public static final A j = new A(1, 8);
    public static final A k = new A(1, 9);
    public static final A l = new A(1, 10);
    public static final A m = new A(1, 11);
    public static final A n = new A(1, 12);
    public static final A o = new A(1, 13);
    public static final A p = new A(1, 14);
    public static final A q = new A(1, 15);
    public static final A r = new A(1, 16);
    public static final A s = new A(1, 17);
    public static final A t = new A(1, 18);
    public static final A u = new A(1, 19);
    public static final A v = new A(1, 20);
    public static final A w = new A(1, 21);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ A(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    /* JADX WARN: Type inference failed for: r12v3, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v50, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v31, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v34, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v57, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r4v40, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r5v20, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r5v31, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r8v6, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i2 = 0;
        List list = null;
        d = null;
        D d2 = null;
        mVar = null;
        androidx.compose.ui.unit.m mVar = null;
        u = null;
        U u2 = null;
        pVar = null;
        androidx.compose.ui.text.style.p pVar = null;
        i = null;
        I i3 = null;
        c1011l = null;
        C1011l c1011l = null;
        c1012m = null;
        C1012m c1012m = null;
        m = null;
        M m2 = null;
        n = null;
        N n2 = null;
        d = null;
        D d3 = null;
        tVar = null;
        t tVar = null;
        list = null;
        switch (this.a) {
            case 0:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list2 = (List) obj;
                Object obj2 = list2.get(1);
                com.quizlet.data.repository.explanations.myexplanations.a aVar = C.b;
                Boolean bool = Boolean.FALSE;
                List list3 = (Intrinsics.b(obj2, bool) || obj2 == null) ? null : (List) ((Function1) aVar.c).invoke(obj2);
                Object obj3 = list2.get(2);
                List list4 = (Intrinsics.b(obj3, bool) || obj3 == null) ? null : (List) ((Function1) aVar.c).invoke(obj3);
                Object obj4 = list2.get(0);
                String str = obj4 != null ? (String) obj4 : null;
                Intrinsics.d(str);
                if (list3 == null || list3.isEmpty()) {
                    list3 = null;
                }
                if (list4 == null || list4.isEmpty()) {
                    list4 = null;
                }
                Object obj5 = list2.get(3);
                if (!Intrinsics.b(obj5, bool) && obj5 != null) {
                    list = (List) ((Function1) aVar.c).invoke(obj5);
                }
                return new C0995g(str, list3, list4, list);
            case 1:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list5 = (List) obj;
                ArrayList arrayList = new ArrayList(list5.size());
                int size = list5.size();
                while (i2 < size) {
                    Object obj6 = list5.get(i2);
                    C0985e c0985e = (Intrinsics.b(obj6, Boolean.FALSE) || obj6 == null) ? null : (C0985e) ((Function1) C.c.c).invoke(obj6);
                    Intrinsics.d(c0985e);
                    arrayList.add(c0985e);
                    i2++;
                }
                return arrayList;
            case 2:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list6 = (List) obj;
                Object obj7 = list6.get(0);
                EnumC0997i enumC0997i = obj7 != null ? (EnumC0997i) obj7 : null;
                Intrinsics.d(enumC0997i);
                Object obj8 = list6.get(2);
                Integer num = obj8 != null ? (Integer) obj8 : null;
                Intrinsics.d(num);
                int iIntValue = num.intValue();
                Object obj9 = list6.get(3);
                Integer num2 = obj9 != null ? (Integer) obj9 : null;
                Intrinsics.d(num2);
                int iIntValue2 = num2.intValue();
                Object obj10 = list6.get(4);
                String str2 = obj10 != null ? (String) obj10 : null;
                Intrinsics.d(str2);
                switch (enumC0997i.ordinal()) {
                    case 0:
                        Object obj11 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = C.h;
                        if (!Intrinsics.b(obj11, Boolean.FALSE) && obj11 != null) {
                            tVar = (t) ((Function1) aVar2.c).invoke(obj11);
                        }
                        Intrinsics.d(tVar);
                        return new C0985e(iIntValue, iIntValue2, tVar, str2);
                    case 1:
                        Object obj12 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar3 = C.i;
                        if (!Intrinsics.b(obj12, Boolean.FALSE) && obj12 != null) {
                            d3 = (D) ((Function1) aVar3.c).invoke(obj12);
                        }
                        Intrinsics.d(d3);
                        return new C0985e(iIntValue, iIntValue2, d3, str2);
                    case 2:
                        Object obj13 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar4 = C.d;
                        if (!Intrinsics.b(obj13, Boolean.FALSE) && obj13 != null) {
                            n2 = (N) ((Function1) aVar4.c).invoke(obj13);
                        }
                        Intrinsics.d(n2);
                        return new C0985e(iIntValue, iIntValue2, n2, str2);
                    case 3:
                        Object obj14 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar5 = C.e;
                        if (!Intrinsics.b(obj14, Boolean.FALSE) && obj14 != null) {
                            m2 = (M) ((Function1) aVar5.c).invoke(obj14);
                        }
                        Intrinsics.d(m2);
                        return new C0985e(iIntValue, iIntValue2, m2, str2);
                    case 4:
                        Object obj15 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar6 = C.f;
                        if (!Intrinsics.b(obj15, Boolean.FALSE) && obj15 != null) {
                            c1012m = (C1012m) ((Function1) aVar6.c).invoke(obj15);
                        }
                        Intrinsics.d(c1012m);
                        return new C0985e(iIntValue, iIntValue2, c1012m, str2);
                    case 5:
                        Object obj16 = list6.get(1);
                        com.quizlet.data.repository.explanations.myexplanations.a aVar7 = C.g;
                        if (!Intrinsics.b(obj16, Boolean.FALSE) && obj16 != null) {
                            c1011l = (C1011l) ((Function1) aVar7.c).invoke(obj16);
                        }
                        Intrinsics.d(c1011l);
                        return new C0985e(iIntValue, iIntValue2, c1011l, str2);
                    case 6:
                        Object obj17 = list6.get(1);
                        String str3 = obj17 != null ? (String) obj17 : null;
                        Intrinsics.d(str3);
                        return new C0985e(iIntValue, iIntValue2, str3, str2);
                    default:
                        throw new NoWhenBranchMatchedException();
                }
            case 3:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Float");
                return new androidx.compose.ui.text.style.a(((Float) obj).floatValue());
            case 4:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list7 = (List) obj;
                Object obj18 = list7.get(0);
                String str4 = obj18 != null ? (String) obj18 : null;
                Intrinsics.d(str4);
                Object obj19 = list7.get(1);
                return new C1011l(str4, (Intrinsics.b(obj19, Boolean.FALSE) || obj19 == null) ? null : (I) ((Function1) C.j.c).invoke(obj19), null);
            case 5:
                if (Intrinsics.b(obj, Boolean.FALSE)) {
                    return new C0861v(C0861v.g);
                }
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Int");
                return new C0861v(androidx.compose.ui.graphics.F.c(((Integer) obj).intValue()));
            case 6:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Int");
                return new androidx.compose.ui.text.font.u(((Integer) obj).intValue());
            case 7:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list8 = (List) obj;
                Object obj20 = list8.get(0);
                String str5 = obj20 != null ? (String) obj20 : null;
                Intrinsics.d(str5);
                Object obj21 = list8.get(1);
                com.quizlet.data.repository.explanations.myexplanations.a aVar8 = C.j;
                if (!Intrinsics.b(obj21, Boolean.FALSE) && obj21 != null) {
                    i3 = (I) ((Function1) aVar8.c).invoke(obj21);
                }
                return new C1012m(str5, i3);
            case 8:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list9 = (List) obj;
                ArrayList arrayList2 = new ArrayList(list9.size());
                int size2 = list9.size();
                while (i2 < size2) {
                    Object obj22 = list9.get(i2);
                    androidx.compose.ui.text.intl.a aVar9 = (Intrinsics.b(obj22, Boolean.FALSE) || obj22 == null) ? null : (androidx.compose.ui.text.intl.a) ((Function1) C.v.c).invoke(obj22);
                    Intrinsics.d(aVar9);
                    arrayList2.add(aVar9);
                    i2++;
                }
                return new androidx.compose.ui.text.intl.b(arrayList2);
            case 9:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.String");
                String str6 = (String) obj;
                androidx.compose.ui.text.intl.c.a.getClass();
                Locale localeForLanguageTag = Locale.forLanguageTag(str6);
                if (Intrinsics.b(localeForLanguageTag.toLanguageTag(), "und")) {
                    Log.e("Locale", "The language tag " + str6 + " is not well-formed. Locale is resolved to Undetermined. Note that underscore '_' is not a valid subtag delimiter and must be replaced with '-'.");
                }
                return new androidx.compose.ui.text.intl.a(localeForLanguageTag);
            case 10:
                if (Intrinsics.b(obj, Boolean.FALSE)) {
                    return new androidx.compose.ui.geometry.b(9205357640488583168L);
                }
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list10 = (List) obj;
                Object obj23 = list10.get(0);
                Float f2 = obj23 != null ? (Float) obj23 : null;
                Intrinsics.d(f2);
                float fFloatValue = f2.floatValue();
                Object obj24 = list10.get(1);
                Float f3 = obj24 != null ? (Float) obj24 : null;
                Intrinsics.d(f3);
                return new androidx.compose.ui.geometry.b(Q4.c(fFloatValue, f3.floatValue()));
            case 11:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list11 = (List) obj;
                Object obj25 = list11.get(0);
                androidx.compose.ui.text.style.i iVar = obj25 != null ? (androidx.compose.ui.text.style.i) obj25 : null;
                Intrinsics.d(iVar);
                Object obj26 = list11.get(1);
                androidx.compose.ui.text.style.k kVar = obj26 != null ? (androidx.compose.ui.text.style.k) obj26 : null;
                Intrinsics.d(kVar);
                Object obj27 = list11.get(2);
                androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
                B b2 = C.s;
                Boolean bool2 = Boolean.FALSE;
                androidx.compose.ui.unit.m mVar2 = ((Intrinsics.b(obj27, bool2) && b2 == null) || obj27 == null) ? null : (androidx.compose.ui.unit.m) b2.b.invoke(obj27);
                Intrinsics.d(mVar2);
                Object obj28 = list11.get(3);
                androidx.compose.ui.text.style.p pVar2 = androidx.compose.ui.text.style.p.c;
                com.quizlet.data.repository.explanations.myexplanations.a aVar10 = C.m;
                if (!Intrinsics.b(obj28, bool2) && obj28 != null) {
                    pVar = (androidx.compose.ui.text.style.p) ((Function1) aVar10.c).invoke(obj28);
                }
                return new t(iVar.a, kVar.a, mVar2.a, pVar, null, null, 0, Integer.MIN_VALUE, null);
            case 12:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list12 = (List) obj;
                Object obj29 = list12.get(0);
                int i4 = C0861v.h;
                B b3 = C.r;
                Boolean bool3 = Boolean.FALSE;
                C0861v c0861v = ((Intrinsics.b(obj29, bool3) && b3 == null) || obj29 == null) ? null : (C0861v) b3.b.invoke(obj29);
                Intrinsics.d(c0861v);
                Object obj30 = list12.get(1);
                B b4 = C.t;
                androidx.compose.ui.geometry.b bVar = ((Intrinsics.b(obj30, bool3) && b4 == null) || obj30 == null) ? null : (androidx.compose.ui.geometry.b) b4.b.invoke(obj30);
                Intrinsics.d(bVar);
                Object obj31 = list12.get(2);
                Float f4 = obj31 != null ? (Float) obj31 : null;
                Intrinsics.d(f4);
                return new U(c0861v.a, bVar.a, f4.floatValue());
            case 13:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list13 = (List) obj;
                Object obj32 = list13.get(0);
                int i5 = C0861v.h;
                B b5 = C.r;
                Boolean bool4 = Boolean.FALSE;
                C0861v c0861v2 = ((Intrinsics.b(obj32, bool4) && b5 == null) || obj32 == null) ? null : (C0861v) b5.b.invoke(obj32);
                Intrinsics.d(c0861v2);
                Object obj33 = list13.get(1);
                androidx.compose.ui.unit.n[] nVarArr2 = androidx.compose.ui.unit.m.b;
                B b6 = C.s;
                androidx.compose.ui.unit.m mVar3 = ((Intrinsics.b(obj33, bool4) && b6 == null) || obj33 == null) ? null : (androidx.compose.ui.unit.m) b6.b.invoke(obj33);
                Intrinsics.d(mVar3);
                Object obj34 = list13.get(2);
                androidx.compose.ui.text.font.u uVar = androidx.compose.ui.text.font.u.b;
                androidx.compose.ui.text.font.u uVar2 = (Intrinsics.b(obj34, bool4) || obj34 == null) ? null : (androidx.compose.ui.text.font.u) ((Function1) C.n.c).invoke(obj34);
                Object obj35 = list13.get(3);
                androidx.compose.ui.text.font.q qVar = obj35 != null ? (androidx.compose.ui.text.font.q) obj35 : null;
                Object obj36 = list13.get(4);
                androidx.compose.ui.text.font.r rVar = obj36 != null ? (androidx.compose.ui.text.font.r) obj36 : null;
                Object obj37 = list13.get(6);
                String str7 = obj37 != null ? (String) obj37 : null;
                Object obj38 = list13.get(7);
                androidx.compose.ui.unit.m mVar4 = ((Intrinsics.b(obj38, bool4) && b6 == null) || obj38 == null) ? null : (androidx.compose.ui.unit.m) b6.b.invoke(obj38);
                Intrinsics.d(mVar4);
                Object obj39 = list13.get(8);
                androidx.compose.ui.text.style.a aVar11 = (Intrinsics.b(obj39, bool4) || obj39 == null) ? null : (androidx.compose.ui.text.style.a) ((Function1) C.o.c).invoke(obj39);
                Object obj40 = list13.get(9);
                androidx.compose.ui.text.style.o oVar = (Intrinsics.b(obj40, bool4) || obj40 == null) ? null : (androidx.compose.ui.text.style.o) ((Function1) C.l.c).invoke(obj40);
                Object obj41 = list13.get(10);
                androidx.compose.ui.text.intl.b bVar2 = androidx.compose.ui.text.intl.b.c;
                androidx.compose.ui.text.intl.b bVar3 = (Intrinsics.b(obj41, bool4) || obj41 == null) ? null : (androidx.compose.ui.text.intl.b) ((Function1) C.u.c).invoke(obj41);
                Object obj42 = list13.get(11);
                C0861v c0861v3 = ((Intrinsics.b(obj42, bool4) && b5 == null) || obj42 == null) ? null : (C0861v) b5.b.invoke(obj42);
                Intrinsics.d(c0861v3);
                Object obj43 = list13.get(12);
                androidx.compose.ui.text.style.j jVar = (Intrinsics.b(obj43, bool4) || obj43 == null) ? null : (androidx.compose.ui.text.style.j) ((Function1) C.k.c).invoke(obj43);
                Object obj44 = list13.get(13);
                U u3 = U.d;
                com.quizlet.data.repository.explanations.myexplanations.a aVar12 = C.q;
                if (!Intrinsics.b(obj44, bool4) && obj44 != null) {
                    u2 = (U) ((Function1) aVar12.c).invoke(obj44);
                }
                return new D(c0861v2.a, mVar3.a, uVar2, qVar, rVar, (androidx.compose.ui.text.font.j) null, str7, mVar4.a, aVar11, oVar, bVar3, c0861v3.a, jVar, u2, 49184);
            case 14:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Int");
                return new androidx.compose.ui.text.style.j(((Integer) obj).intValue());
            case 15:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Float>");
                List list14 = (List) obj;
                return new androidx.compose.ui.text.style.o(((Number) list14.get(0)).floatValue(), ((Number) list14.get(1)).floatValue());
            case 16:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list15 = (List) obj;
                Object obj45 = list15.get(0);
                androidx.compose.ui.unit.n[] nVarArr3 = androidx.compose.ui.unit.m.b;
                B b7 = C.s;
                Boolean bool5 = Boolean.FALSE;
                androidx.compose.ui.unit.m mVar5 = ((Intrinsics.b(obj45, bool5) && b7 == null) || obj45 == null) ? null : (androidx.compose.ui.unit.m) b7.b.invoke(obj45);
                Intrinsics.d(mVar5);
                Object obj46 = list15.get(1);
                if ((!Intrinsics.b(obj46, bool5) || b7 != null) && obj46 != null) {
                    mVar = (androidx.compose.ui.unit.m) b7.b.invoke(obj46);
                }
                Intrinsics.d(mVar);
                return new androidx.compose.ui.text.style.p(mVar5.a, mVar.a);
            case 17:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any?>");
                List list16 = (List) obj;
                Object obj47 = list16.get(0);
                com.quizlet.data.repository.explanations.myexplanations.a aVar13 = C.i;
                Boolean bool6 = Boolean.FALSE;
                D d4 = (Intrinsics.b(obj47, bool6) || obj47 == null) ? null : (D) ((Function1) aVar13.c).invoke(obj47);
                Object obj48 = list16.get(1);
                D d5 = (Intrinsics.b(obj48, bool6) || obj48 == null) ? null : (D) ((Function1) aVar13.c).invoke(obj48);
                Object obj49 = list16.get(2);
                D d6 = (Intrinsics.b(obj49, bool6) || obj49 == null) ? null : (D) ((Function1) aVar13.c).invoke(obj49);
                Object obj50 = list16.get(3);
                if (!Intrinsics.b(obj50, bool6) && obj50 != null) {
                    d2 = (D) ((Function1) aVar13.c).invoke(obj50);
                }
                return new I(d4, d5, d6, d2);
            case 18:
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list17 = (List) obj;
                Object obj51 = list17.get(0);
                Integer num3 = obj51 != null ? (Integer) obj51 : null;
                Intrinsics.d(num3);
                int iIntValue3 = num3.intValue();
                Object obj52 = list17.get(1);
                Integer num4 = obj52 != null ? (Integer) obj52 : null;
                Intrinsics.d(num4);
                return new K(AbstractC3205m5.c(iIntValue3, num4.intValue()));
            case 19:
                if (Intrinsics.b(obj, Boolean.FALSE)) {
                    return new androidx.compose.ui.unit.m(androidx.compose.ui.unit.m.c);
                }
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Any>");
                List list18 = (List) obj;
                Object obj53 = list18.get(0);
                Float f5 = obj53 != null ? (Float) obj53 : null;
                Intrinsics.d(f5);
                float fFloatValue2 = f5.floatValue();
                Object obj54 = list18.get(1);
                androidx.compose.ui.unit.n nVar = obj54 != null ? (androidx.compose.ui.unit.n) obj54 : null;
                Intrinsics.d(nVar);
                return new androidx.compose.ui.unit.m(S5.i(nVar.a, fFloatValue2));
            case 20:
                String str8 = obj != null ? (String) obj : null;
                Intrinsics.d(str8);
                return new M(str8);
            default:
                String str9 = obj != null ? (String) obj : null;
                Intrinsics.d(str9);
                return new N(str9);
        }
    }
}

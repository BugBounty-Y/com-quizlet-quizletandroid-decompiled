package androidx.compose.ui.text;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.U;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z extends kotlin.jvm.internal.r implements Function2 {
    public static final z b = new z(2, 0);
    public static final z c = new z(2, 1);
    public static final z d = new z(2, 2);
    public static final z e = new z(2, 3);
    public static final z f = new z(2, 4);
    public static final z g = new z(2, 5);
    public static final z h = new z(2, 6);
    public static final z i = new z(2, 7);
    public static final z j = new z(2, 8);
    public static final z k = new z(2, 9);
    public static final z l = new z(2, 10);
    public static final z m = new z(2, 11);
    public static final z n = new z(2, 12);
    public static final z o = new z(2, 13);
    public static final z p = new z(2, 14);
    public static final z q = new z(2, 15);
    public static final z r = new z(2, 16);
    public static final z s = new z(2, 17);
    public static final z t = new z(2, 18);
    public static final z u = new z(2, 19);
    public static final z v = new z(2, 20);
    public static final z w = new z(2, 21);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ z(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i2 = 0;
        switch (this.a) {
            case 0:
                androidx.compose.runtime.saveable.b bVar = (androidx.compose.runtime.saveable.b) obj;
                C0995g c0995g = (C0995g) obj2;
                String str = c0995g.a;
                com.quizlet.data.repository.explanations.myexplanations.a aVar = C.a;
                List listB = c0995g.b();
                com.quizlet.data.repository.explanations.myexplanations.a aVar2 = C.b;
                Object objA = C.a(listB, aVar2, bVar);
                Object obj3 = c0995g.c;
                if (obj3 == null) {
                    obj3 = kotlin.collections.K.a;
                }
                return kotlin.collections.B.f(str, objA, C.a(obj3, aVar2, bVar), C.a(c0995g.d, aVar2, bVar));
            case 1:
                androidx.compose.runtime.saveable.b bVar2 = (androidx.compose.runtime.saveable.b) obj;
                List list = (List) obj2;
                ArrayList arrayList = new ArrayList(list.size());
                int size = list.size();
                while (i2 < size) {
                    arrayList.add(C.a((C0985e) list.get(i2), C.c, bVar2));
                    i2++;
                }
                return arrayList;
            case 2:
                androidx.compose.runtime.saveable.b bVar3 = (androidx.compose.runtime.saveable.b) obj;
                C0985e c0985e = (C0985e) obj2;
                Object obj4 = c0985e.a;
                EnumC0997i enumC0997i = obj4 instanceof t ? EnumC0997i.a : obj4 instanceof D ? EnumC0997i.b : obj4 instanceof N ? EnumC0997i.c : obj4 instanceof M ? EnumC0997i.d : obj4 instanceof C1012m ? EnumC0997i.e : obj4 instanceof C1011l ? EnumC0997i.f : EnumC0997i.g;
                int iOrdinal = enumC0997i.ordinal();
                Object objA2 = c0985e.a;
                switch (iOrdinal) {
                    case 0:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.ParagraphStyle");
                        objA2 = C.a((t) objA2, C.h, bVar3);
                        break;
                    case 1:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.SpanStyle");
                        objA2 = C.a((D) objA2, C.i, bVar3);
                        break;
                    case 2:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.VerbatimTtsAnnotation");
                        objA2 = C.a((N) objA2, C.d, bVar3);
                        break;
                    case 3:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.UrlAnnotation");
                        objA2 = C.a((M) objA2, C.e, bVar3);
                        break;
                    case 4:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.LinkAnnotation.Url");
                        objA2 = C.a((C1012m) objA2, C.f, bVar3);
                        break;
                    case 5:
                        Intrinsics.e(objA2, "null cannot be cast to non-null type androidx.compose.ui.text.LinkAnnotation.Clickable");
                        objA2 = C.a((C1011l) objA2, C.g, bVar3);
                        break;
                    case 6:
                        com.quizlet.data.repository.explanations.myexplanations.a aVar3 = C.a;
                        break;
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                return kotlin.collections.B.f(enumC0997i, objA2, Integer.valueOf(c0985e.b), Integer.valueOf(c0985e.c), c0985e.d);
            case 3:
                return Float.valueOf(((androidx.compose.ui.text.style.a) obj2).a);
            case 4:
                C1011l c1011l = (C1011l) obj2;
                return kotlin.collections.B.f(c1011l.a, C.a(c1011l.b, C.j, (androidx.compose.runtime.saveable.b) obj));
            case 5:
                long j2 = ((C0861v) obj2).a;
                return j2 == 16 ? Boolean.FALSE : Integer.valueOf(androidx.compose.ui.graphics.F.A(j2));
            case 6:
                return Integer.valueOf(((androidx.compose.ui.text.font.u) obj2).a);
            case 7:
                C1012m c1012m = (C1012m) obj2;
                return kotlin.collections.B.f(c1012m.a, C.a(c1012m.b, C.j, (androidx.compose.runtime.saveable.b) obj));
            case 8:
                androidx.compose.runtime.saveable.b bVar4 = (androidx.compose.runtime.saveable.b) obj;
                List list2 = ((androidx.compose.ui.text.intl.b) obj2).a;
                ArrayList arrayList2 = new ArrayList(list2.size());
                int size2 = list2.size();
                while (i2 < size2) {
                    arrayList2.add(C.a((androidx.compose.ui.text.intl.a) list2.get(i2), C.v, bVar4));
                    i2++;
                }
                return arrayList2;
            case 9:
                return ((androidx.compose.ui.text.intl.a) obj2).a.toLanguageTag();
            case 10:
                long j3 = ((androidx.compose.ui.geometry.b) obj2).a;
                if (androidx.compose.ui.geometry.b.b(j3, 9205357640488583168L)) {
                    return Boolean.FALSE;
                }
                Float fValueOf = Float.valueOf(androidx.compose.ui.geometry.b.d(j3));
                com.quizlet.data.repository.explanations.myexplanations.a aVar4 = C.a;
                return kotlin.collections.B.f(fValueOf, Float.valueOf(androidx.compose.ui.geometry.b.e(j3)));
            case 11:
                androidx.compose.runtime.saveable.b bVar5 = (androidx.compose.runtime.saveable.b) obj;
                t tVar = (t) obj2;
                androidx.compose.ui.text.style.i iVar = new androidx.compose.ui.text.style.i(tVar.a);
                com.quizlet.data.repository.explanations.myexplanations.a aVar5 = C.a;
                androidx.compose.ui.text.style.k kVar = new androidx.compose.ui.text.style.k(tVar.b);
                Object objA3 = C.a(new androidx.compose.ui.unit.m(tVar.c), C.s, bVar5);
                androidx.compose.ui.text.style.p pVar = androidx.compose.ui.text.style.p.c;
                return kotlin.collections.B.f(iVar, kVar, objA3, C.a(tVar.d, C.m, bVar5));
            case 12:
                androidx.compose.runtime.saveable.b bVar6 = (androidx.compose.runtime.saveable.b) obj;
                U u2 = (U) obj2;
                return kotlin.collections.B.f(C.a(new C0861v(u2.a), C.r, bVar6), C.a(new androidx.compose.ui.geometry.b(u2.b), C.t, bVar6), Float.valueOf(u2.c));
            case 13:
                androidx.compose.runtime.saveable.b bVar7 = (androidx.compose.runtime.saveable.b) obj;
                D d2 = (D) obj2;
                C0861v c0861v = new C0861v(d2.a.b());
                B b2 = C.r;
                Object objA4 = C.a(c0861v, b2, bVar7);
                androidx.compose.ui.unit.m mVar = new androidx.compose.ui.unit.m(d2.b);
                B b3 = C.s;
                Object objA5 = C.a(mVar, b3, bVar7);
                androidx.compose.ui.text.font.u uVar = androidx.compose.ui.text.font.u.b;
                Object objA6 = C.a(d2.c, C.n, bVar7);
                Object objA7 = C.a(new androidx.compose.ui.unit.m(d2.h), b3, bVar7);
                Object objA8 = C.a(d2.i, C.o, bVar7);
                Object objA9 = C.a(d2.j, C.l, bVar7);
                androidx.compose.ui.text.intl.b bVar8 = androidx.compose.ui.text.intl.b.c;
                Object objA10 = C.a(d2.k, C.u, bVar7);
                Object objA11 = C.a(new C0861v(d2.l), b2, bVar7);
                Object objA12 = C.a(d2.m, C.k, bVar7);
                U u3 = U.d;
                return kotlin.collections.B.f(objA4, objA5, objA6, d2.d, d2.e, -1, d2.g, objA7, objA8, objA9, objA10, objA11, objA12, C.a(d2.n, C.q, bVar7));
            case 14:
                return Integer.valueOf(((androidx.compose.ui.text.style.j) obj2).a);
            case 15:
                androidx.compose.ui.text.style.o oVar = (androidx.compose.ui.text.style.o) obj2;
                return kotlin.collections.B.f(Float.valueOf(oVar.a), Float.valueOf(oVar.b));
            case 16:
                androidx.compose.runtime.saveable.b bVar9 = (androidx.compose.runtime.saveable.b) obj;
                androidx.compose.ui.text.style.p pVar2 = (androidx.compose.ui.text.style.p) obj2;
                androidx.compose.ui.unit.m mVar2 = new androidx.compose.ui.unit.m(pVar2.a);
                B b4 = C.s;
                return kotlin.collections.B.f(C.a(mVar2, b4, bVar9), C.a(new androidx.compose.ui.unit.m(pVar2.b), b4, bVar9));
            case 17:
                androidx.compose.runtime.saveable.b bVar10 = (androidx.compose.runtime.saveable.b) obj;
                I i3 = (I) obj2;
                D d3 = i3.a;
                com.quizlet.data.repository.explanations.myexplanations.a aVar6 = C.i;
                return kotlin.collections.B.f(C.a(d3, aVar6, bVar10), C.a(i3.b, aVar6, bVar10), C.a(i3.c, aVar6, bVar10), C.a(i3.d, aVar6, bVar10));
            case 18:
                long j4 = ((K) obj2).a;
                int i4 = K.c;
                Integer numValueOf = Integer.valueOf((int) (j4 >> 32));
                com.quizlet.data.repository.explanations.myexplanations.a aVar7 = C.a;
                return kotlin.collections.B.f(numValueOf, Integer.valueOf((int) (j4 & 4294967295L)));
            case 19:
                long j5 = ((androidx.compose.ui.unit.m) obj2).a;
                if (androidx.compose.ui.unit.m.a(j5, androidx.compose.ui.unit.m.c)) {
                    return Boolean.FALSE;
                }
                Float fValueOf2 = Float.valueOf(androidx.compose.ui.unit.m.c(j5));
                com.quizlet.data.repository.explanations.myexplanations.a aVar8 = C.a;
                return kotlin.collections.B.f(fValueOf2, new androidx.compose.ui.unit.n(androidx.compose.ui.unit.m.b(j5)));
            case 20:
                String str2 = ((M) obj2).a;
                com.quizlet.data.repository.explanations.myexplanations.a aVar9 = C.a;
                return str2;
            default:
                String str3 = ((N) obj2).a;
                com.quizlet.data.repository.explanations.myexplanations.a aVar10 = C.a;
                return str3;
        }
    }
}

package androidx.compose.ui.focus;

import android.graphics.Rect;
import android.view.FocusFinder;
import android.view.View;
import android.view.ViewGroup;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.text.X;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.V;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.node.o0;
import androidx.compose.ui.platform.C0971v;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final int[] a = new int[2];

    public static final int A(t tVar, int i) {
        androidx.compose.ui.p pVar;
        V v;
        int iOrdinal = tVar.N0().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                t tVarP = p(tVar);
                if (tVarP != null) {
                    return y(tVarP, i);
                }
                throw new IllegalArgumentException("ActiveParent with no focused child");
            }
            if (iOrdinal != 2) {
                if (iOrdinal != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                androidx.compose.ui.p pVar2 = tVar.a;
                if (!pVar2.m) {
                    throw new IllegalStateException("visitAncestors called on an unattached node");
                }
                androidx.compose.ui.p pVar3 = pVar2.e;
                E eV = AbstractC0910f.v(tVar);
                loop0: while (true) {
                    pVar = null;
                    if (eV == null) {
                        break;
                    }
                    if ((((androidx.compose.ui.p) eV.w.f).d & 1024) != 0) {
                        while (pVar3 != null) {
                            if ((pVar3.c & 1024) != 0) {
                                androidx.compose.ui.p pVarF = pVar3;
                                androidx.compose.runtime.collection.b bVar = null;
                                while (pVarF != null) {
                                    if (pVarF instanceof t) {
                                        pVar = pVarF;
                                        break loop0;
                                    }
                                    if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                        int i2 = 0;
                                        for (androidx.compose.ui.p pVar4 = ((AbstractC0918n) pVarF).o; pVar4 != null; pVar4 = pVar4.f) {
                                            if ((pVar4.c & 1024) != 0) {
                                                i2++;
                                                if (i2 == 1) {
                                                    pVarF = pVar4;
                                                } else {
                                                    if (bVar == null) {
                                                        bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                    }
                                                    if (pVarF != null) {
                                                        bVar.b(pVarF);
                                                        pVarF = null;
                                                    }
                                                    bVar.b(pVar4);
                                                }
                                            }
                                        }
                                        if (i2 == 1) {
                                        }
                                    }
                                    pVarF = AbstractC0910f.f(bVar);
                                }
                            }
                            pVar3 = pVar3.e;
                        }
                    }
                    eV = eV.s();
                    pVar3 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
                }
                t tVar2 = (t) pVar;
                if (tVar2 != null) {
                    int iOrdinal2 = tVar2.N0().ordinal();
                    if (iOrdinal2 == 0) {
                        return z(tVar2, i);
                    }
                    if (iOrdinal2 == 1) {
                        return A(tVar2, i);
                    }
                    if (iOrdinal2 == 2) {
                        return 2;
                    }
                    if (iOrdinal2 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    int iA = A(tVar2, i);
                    int i3 = iA != 1 ? iA : 0;
                    return i3 == 0 ? z(tVar2, i) : i3;
                }
            }
        }
        return 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:63:0x00c8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean B(androidx.compose.ui.focus.t r10) {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.B(androidx.compose.ui.focus.t):boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v2, types: [java.lang.Object, java.lang.Object[]] */
    public static final boolean C(t tVar, androidx.activity.compose.g gVar) {
        t[] tVarArr = new t[16];
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitChildren called on an unattached node");
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            AbstractC0910f.b(bVar, pVar);
        } else {
            bVar.b(pVar2);
        }
        int i = 0;
        while (bVar.m()) {
            androidx.compose.ui.p pVarF = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
            if ((pVarF.d & 1024) == 0) {
                AbstractC0910f.b(bVar, pVarF);
            } else {
                while (true) {
                    if (pVarF == null) {
                        break;
                    }
                    if ((pVarF.c & 1024) != 0) {
                        androidx.compose.runtime.collection.b bVar2 = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                int i2 = i + 1;
                                if (tVarArr.length < i2) {
                                    int length = tVarArr.length;
                                    ?? r10 = new Object[Math.max(i2, length * 2)];
                                    System.arraycopy(tVarArr, 0, r10, 0, length);
                                    tVarArr = r10;
                                }
                                tVarArr[i] = tVar2;
                                i = i2;
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i3 = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i3++;
                                        if (i3 == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar2 == null) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar2.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar2.b(pVar3);
                                        }
                                    }
                                }
                                if (i3 == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar2);
                        }
                    } else {
                        pVarF = pVarF.f;
                    }
                }
            }
        }
        v comparator = v.a;
        Intrinsics.checkNotNullParameter(tVarArr, "<this>");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        Arrays.sort(tVarArr, 0, i, comparator);
        if (i > 0) {
            int i4 = i - 1;
            do {
                t tVar3 = tVarArr[i4];
                if (v(tVar3) && a(tVar3, gVar)) {
                    return true;
                }
                i4--;
            } while (i4 >= 0);
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v2, types: [java.lang.Object, java.lang.Object[]] */
    public static final boolean D(t tVar, androidx.activity.compose.g gVar) {
        t[] tVarArr = new t[16];
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitChildren called on an unattached node");
        }
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            AbstractC0910f.b(bVar, pVar);
        } else {
            bVar.b(pVar2);
        }
        int i = 0;
        while (bVar.m()) {
            androidx.compose.ui.p pVarF = (androidx.compose.ui.p) bVar.o(bVar.c - 1);
            if ((pVarF.d & 1024) == 0) {
                AbstractC0910f.b(bVar, pVarF);
            } else {
                while (true) {
                    if (pVarF == null) {
                        break;
                    }
                    if ((pVarF.c & 1024) != 0) {
                        androidx.compose.runtime.collection.b bVar2 = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                int i2 = i + 1;
                                if (tVarArr.length < i2) {
                                    int length = tVarArr.length;
                                    ?? r10 = new Object[Math.max(i2, length * 2)];
                                    System.arraycopy(tVarArr, 0, r10, 0, length);
                                    tVarArr = r10;
                                }
                                tVarArr[i] = tVar2;
                                i = i2;
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i3 = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i3++;
                                        if (i3 == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar2 == null) {
                                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar2.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar2.b(pVar3);
                                        }
                                    }
                                }
                                if (i3 == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar2);
                        }
                    } else {
                        pVarF = pVarF.f;
                    }
                }
            }
        }
        v comparator = v.a;
        Intrinsics.checkNotNullParameter(tVarArr, "<this>");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        Arrays.sort(tVarArr, 0, i, comparator);
        if (i > 0) {
            int i4 = 0;
            do {
                t tVar3 = tVarArr[i4];
                if (v(tVar3) && l(tVar3, gVar)) {
                    return true;
                }
                i4++;
            } while (i4 < i);
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v17 */
    /* JADX WARN: Type inference failed for: r2v18 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v10 */
    /* JADX WARN: Type inference failed for: r4v11 */
    /* JADX WARN: Type inference failed for: r4v12 */
    /* JADX WARN: Type inference failed for: r4v13 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3 */
    /* JADX WARN: Type inference failed for: r4v4, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6 */
    /* JADX WARN: Type inference failed for: r4v7, types: [androidx.compose.runtime.collection.b] */
    public static final void E(t tVar) {
        V v;
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        E eV = AbstractC0910f.v(tVar);
        androidx.compose.ui.p pVar2 = pVar;
        while (eV != null) {
            if ((((androidx.compose.ui.p) eV.w.f).d & 5120) != 0) {
                while (pVar2 != null) {
                    int i = pVar2.c;
                    if ((i & 5120) != 0) {
                        if (pVar2 != pVar && (i & 1024) != 0) {
                            return;
                        }
                        if ((i & 4096) != 0) {
                            AbstractC0918n abstractC0918nF = pVar2;
                            ?? bVar = 0;
                            while (abstractC0918nF != 0) {
                                if (abstractC0918nF instanceof d) {
                                    d dVar = (d) abstractC0918nF;
                                    dVar.d0(q(dVar));
                                } else if ((abstractC0918nF.c & 4096) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar3 = abstractC0918nF.o;
                                    int i2 = 0;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                    while (pVar3 != null) {
                                        if ((pVar3.c & 4096) != 0) {
                                            i2++;
                                            bVar = bVar;
                                            if (i2 == 1) {
                                                abstractC0918nF = pVar3;
                                            } else {
                                                if (bVar == 0) {
                                                    bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (abstractC0918nF != 0) {
                                                    bVar.b(abstractC0918nF);
                                                    abstractC0918nF = 0;
                                                }
                                                bVar.b(pVar3);
                                            }
                                        }
                                        pVar3 = pVar3.f;
                                        abstractC0918nF = abstractC0918nF;
                                        bVar = bVar;
                                    }
                                    if (i2 == 1) {
                                    }
                                }
                                abstractC0918nF = AbstractC0910f.f(bVar);
                            }
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v = eV.w) == null) ? null : (o0) v.e;
        }
    }

    public static final Boolean F(t tVar, int i) {
        Boolean boolValueOf;
        com.bumptech.glide.manager.p pVarI = I(tVar);
        u uVar = new u(tVar, 1);
        try {
            if (pVarI.a) {
                com.bumptech.glide.manager.p.a(pVarI);
            }
            pVarI.a = true;
            ((androidx.compose.runtime.collection.b) pVarI.c).b(uVar);
            int iK = AbstractC0147y.k(A(tVar, i));
            if (iK == 0) {
                boolValueOf = Boolean.valueOf(B(tVar));
            } else if (iK == 1) {
                boolValueOf = null;
            } else if (iK == 2) {
                boolValueOf = Boolean.TRUE;
            } else {
                if (iK != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                boolValueOf = null;
            }
            return boolValueOf;
        } finally {
            com.bumptech.glide.manager.p.d(pVarI);
        }
    }

    public static final boolean G(t tVar, t tVar2) {
        androidx.compose.ui.p pVarF;
        androidx.compose.ui.p pVarF2;
        V v;
        V v2;
        androidx.compose.ui.p pVar = tVar2.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitAncestors called on an unattached node");
        }
        androidx.compose.ui.p pVar2 = pVar.e;
        E eV = AbstractC0910f.v(tVar2);
        loop0: while (true) {
            if (eV == null) {
                pVarF = null;
                break;
            }
            if ((((androidx.compose.ui.p) eV.w.f).d & 1024) != 0) {
                while (pVar2 != null) {
                    if ((pVar2.c & 1024) != 0) {
                        pVarF = pVar2;
                        androidx.compose.runtime.collection.b bVar = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                break loop0;
                            }
                            if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i++;
                                        if (i == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar == null) {
                                                bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar.b(pVar3);
                                        }
                                    }
                                }
                                if (i == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar);
                        }
                    }
                    pVar2 = pVar2.e;
                }
            }
            eV = eV.s();
            pVar2 = (eV == null || (v2 = eV.w) == null) ? null : (o0) v2.e;
        }
        if (!Intrinsics.b(pVarF, tVar)) {
            throw new IllegalStateException("Non child node cannot request focus.");
        }
        int iOrdinal = tVar.N0().ordinal();
        s sVar = s.b;
        if (iOrdinal == 0) {
            r(tVar2);
            tVar.R0(sVar);
            return true;
        }
        if (iOrdinal == 1) {
            if (p(tVar) == null) {
                throw new IllegalArgumentException("ActiveParent with no focused child");
            }
            t tVarP = p(tVar);
            if (tVarP != null ? e(tVarP, false) : true) {
                r(tVar2);
                return true;
            }
        } else if (iOrdinal != 2) {
            if (iOrdinal != 3) {
                throw new NoWhenBranchMatchedException();
            }
            androidx.compose.ui.p pVar4 = tVar.a;
            if (!pVar4.m) {
                throw new IllegalStateException("visitAncestors called on an unattached node");
            }
            androidx.compose.ui.p pVar5 = pVar4.e;
            E eV2 = AbstractC0910f.v(tVar);
            loop4: while (true) {
                if (eV2 == null) {
                    pVarF2 = null;
                    break;
                }
                if ((((androidx.compose.ui.p) eV2.w.f).d & 1024) != 0) {
                    while (pVar5 != null) {
                        if ((pVar5.c & 1024) != 0) {
                            pVarF2 = pVar5;
                            androidx.compose.runtime.collection.b bVar2 = null;
                            while (pVarF2 != null) {
                                if (pVarF2 instanceof t) {
                                    break loop4;
                                }
                                if ((pVarF2.c & 1024) != 0 && (pVarF2 instanceof AbstractC0918n)) {
                                    int i2 = 0;
                                    for (androidx.compose.ui.p pVar6 = ((AbstractC0918n) pVarF2).o; pVar6 != null; pVar6 = pVar6.f) {
                                        if ((pVar6.c & 1024) != 0) {
                                            i2++;
                                            if (i2 == 1) {
                                                pVarF2 = pVar6;
                                            } else {
                                                if (bVar2 == null) {
                                                    bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (pVarF2 != null) {
                                                    bVar2.b(pVarF2);
                                                    pVarF2 = null;
                                                }
                                                bVar2.b(pVar6);
                                            }
                                        }
                                    }
                                    if (i2 == 1) {
                                    }
                                }
                                pVarF2 = AbstractC0910f.f(bVar2);
                            }
                        }
                        pVar5 = pVar5.e;
                    }
                }
                eV2 = eV2.s();
                pVar5 = (eV2 == null || (v = eV2.w) == null) ? null : (o0) v.e;
            }
            t tVar3 = (t) pVarF2;
            if (tVar3 == null && ((Boolean) ((j) ((C0971v) AbstractC0910f.w(tVar)).getFocusOwner()).a.invoke(null, null)).booleanValue()) {
                r(tVar2);
                tVar.R0(sVar);
                return true;
            }
            if (tVar3 != null && G(tVar3, tVar)) {
                boolean zG = G(tVar, tVar2);
                if (tVar.N0() != sVar) {
                    throw new IllegalStateException("Deactivated node is focused");
                }
                if (zG) {
                    E(tVar3);
                }
                return zG;
            }
        }
        return false;
    }

    public static final boolean H(View view, Integer num, Rect rect) {
        if (num == null) {
            return view.requestFocus();
        }
        if (!(view instanceof ViewGroup)) {
            return view.requestFocus(num.intValue(), rect);
        }
        ViewGroup viewGroup = (ViewGroup) view;
        if (viewGroup.isFocused()) {
            return true;
        }
        if ((!viewGroup.isFocusable() || view.hasFocus()) && !(view instanceof C0971v)) {
            if (rect != null) {
                View viewFindNextFocusFromRect = FocusFinder.getInstance().findNextFocusFromRect(viewGroup, rect, num.intValue());
                return viewFindNextFocusFromRect != null ? viewFindNextFocusFromRect.requestFocus(num.intValue(), rect) : view.requestFocus(num.intValue(), rect);
            }
            View viewFindNextFocus = FocusFinder.getInstance().findNextFocus(viewGroup, view.hasFocus() ? view.findFocus() : null, num.intValue());
            return viewFindNextFocus != null ? viewFindNextFocus.requestFocus(num.intValue()) : view.requestFocus(num.intValue());
        }
        return view.requestFocus(num.intValue(), rect);
    }

    public static final com.bumptech.glide.manager.p I(t tVar) {
        return ((j) ((C0971v) AbstractC0910f.w(tVar)).getFocusOwner()).h;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00a6 A[PHI: r0
  0x00a6: PHI (r0v17 int) = (r0v4 int), (r0v5 int), (r0v6 int), (r0v7 int), (r0v8 int) binds: [B:53:0x00a4, B:56:0x00a9, B:59:0x00ad, B:62:0x00b1, B:65:0x00b5] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object J(androidx.compose.ui.focus.t r9, int r10, kotlin.jvm.functions.Function1 r11) {
        /*
            Method dump skipped, instructions count: 336
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.J(androidx.compose.ui.focus.t, int, kotlin.jvm.functions.Function1):java.lang.Object");
    }

    public static final boolean K(int i, androidx.activity.compose.g gVar, t tVar, androidx.compose.ui.geometry.c cVar) {
        t tVarH;
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new t[16]);
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitChildren called on an unattached node");
        }
        androidx.compose.runtime.collection.b bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            AbstractC0910f.b(bVar2, pVar);
        } else {
            bVar2.b(pVar2);
        }
        while (bVar2.m()) {
            androidx.compose.ui.p pVarF = (androidx.compose.ui.p) bVar2.o(bVar2.c - 1);
            if ((pVarF.d & 1024) == 0) {
                AbstractC0910f.b(bVar2, pVarF);
            } else {
                while (true) {
                    if (pVarF == null) {
                        break;
                    }
                    if ((pVarF.c & 1024) != 0) {
                        androidx.compose.runtime.collection.b bVar3 = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                if (tVar2.m) {
                                    bVar.b(tVar2);
                                }
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i2 = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i2++;
                                        if (i2 == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar3 == null) {
                                                bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar3.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar3.b(pVar3);
                                        }
                                    }
                                }
                                if (i2 == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar3);
                        }
                    } else {
                        pVarF = pVarF.f;
                    }
                }
            }
        }
        while (bVar.m() && (tVarH = h(bVar, cVar, i)) != null) {
            if (tVarH.M0().a) {
                return ((Boolean) gVar.invoke(tVarH)).booleanValue();
            }
            if (n(i, gVar, tVarH, cVar)) {
                return true;
            }
            bVar.n(tVarH);
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:74:0x0105, code lost:
    
        return true;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01a9  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0126  */
    /* JADX WARN: Type inference failed for: r11v2, types: [java.lang.Object, java.lang.Object[]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean L(androidx.compose.ui.focus.t r12, androidx.compose.ui.focus.t r13, int r14, androidx.activity.compose.g r15) {
        /*
            Method dump skipped, instructions count: 458
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.L(androidx.compose.ui.focus.t, androidx.compose.ui.focus.t, int, androidx.activity.compose.g):boolean");
    }

    public static final Integer M(int i) {
        if (i == 5) {
            return 33;
        }
        if (i == 6) {
            return 130;
        }
        if (i == 3) {
            return 17;
        }
        if (i == 4) {
            return 66;
        }
        if (i == 1) {
            return 2;
        }
        return i == 2 ? 1 : null;
    }

    public static final c N(int i) {
        if (i == 1) {
            return new c(2);
        }
        if (i == 2) {
            return new c(1);
        }
        if (i == 17) {
            return new c(3);
        }
        if (i == 33) {
            return new c(5);
        }
        if (i == 66) {
            return new c(4);
        }
        if (i != 130) {
            return null;
        }
        return new c(6);
    }

    public static final Boolean O(int i, androidx.activity.compose.g gVar, t tVar, androidx.compose.ui.geometry.c cVar) {
        int iOrdinal = tVar.N0().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                t tVarP = p(tVar);
                if (tVarP == null) {
                    throw new IllegalStateException("ActiveParent must have a focusedChild");
                }
                int iOrdinal2 = tVarP.N0().ordinal();
                if (iOrdinal2 != 0) {
                    if (iOrdinal2 == 1) {
                        Boolean boolO = O(i, gVar, tVarP, cVar);
                        if (!Intrinsics.b(boolO, Boolean.FALSE)) {
                            return boolO;
                        }
                        if (cVar == null) {
                            if (tVarP.N0() != s.b) {
                                throw new IllegalStateException("Searching for active node in inactive hierarchy");
                            }
                            t tVarG = g(tVarP);
                            if (tVarG == null) {
                                throw new IllegalStateException("ActiveParent must have a focusedChild");
                            }
                            cVar = j(tVarG);
                        }
                        return Boolean.valueOf(n(i, gVar, tVar, cVar));
                    }
                    if (iOrdinal2 != 2) {
                        if (iOrdinal2 != 3) {
                            throw new NoWhenBranchMatchedException();
                        }
                        throw new IllegalStateException("ActiveParent must have a focusedChild");
                    }
                }
                if (cVar == null) {
                    cVar = j(tVarP);
                }
                return Boolean.valueOf(n(i, gVar, tVar, cVar));
            }
            if (iOrdinal != 2) {
                if (iOrdinal == 3) {
                    return tVar.M0().a ? (Boolean) gVar.invoke(tVar) : cVar == null ? Boolean.valueOf(i(tVar, i, gVar)) : Boolean.valueOf(K(i, gVar, tVar, cVar));
                }
                throw new NoWhenBranchMatchedException();
            }
        }
        return Boolean.valueOf(i(tVar, i, gVar));
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x007c A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean a(androidx.compose.ui.focus.t r7, androidx.activity.compose.g r8) {
        /*
            androidx.compose.ui.focus.s r0 = r7.N0()
            int r0 = r0.ordinal()
            if (r0 == 0) goto L89
            r1 = 3
            r2 = 0
            r3 = 2
            r4 = 1
            if (r0 == r4) goto L37
            if (r0 == r3) goto L89
            if (r0 != r1) goto L31
            boolean r0 = C(r7, r8)
            if (r0 != 0) goto L7d
            androidx.compose.ui.focus.l r0 = r7.M0()
            boolean r0 = r0.a
            if (r0 == 0) goto L2d
            java.lang.Object r7 = r8.invoke(r7)
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            goto L2e
        L2d:
            r7 = r2
        L2e:
            if (r7 == 0) goto L7c
            goto L7d
        L31:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        L37:
            androidx.compose.ui.focus.t r0 = p(r7)
            java.lang.String r5 = "ActiveParent must have a focusedChild"
            if (r0 == 0) goto L83
            androidx.compose.ui.focus.s r6 = r0.N0()
            int r6 = r6.ordinal()
            if (r6 == 0) goto L7e
            if (r6 == r4) goto L5b
            if (r6 == r3) goto L7e
            if (r6 == r1) goto L55
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        L55:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            r7.<init>(r5)
            throw r7
        L5b:
            boolean r1 = a(r0, r8)
            if (r1 != 0) goto L7d
            boolean r7 = o(r7, r0, r3, r8)
            if (r7 != 0) goto L7d
            androidx.compose.ui.focus.l r7 = r0.M0()
            boolean r7 = r7.a
            if (r7 == 0) goto L7c
            java.lang.Object r7 = r8.invoke(r0)
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L7c
            goto L7d
        L7c:
            return r2
        L7d:
            return r4
        L7e:
            boolean r7 = o(r7, r0, r3, r8)
            return r7
        L83:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            r7.<init>(r5)
            throw r7
        L89:
            boolean r7 = C(r7, r8)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.a(androidx.compose.ui.focus.t, androidx.activity.compose.g):boolean");
    }

    public static final boolean b(androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2, androidx.compose.ui.geometry.c cVar3, int i) {
        float f;
        float f2;
        if (c(i, cVar3, cVar) || !c(i, cVar2, cVar)) {
            return false;
        }
        float f3 = cVar3.b;
        float f4 = cVar3.d;
        float f5 = cVar3.a;
        float f6 = cVar3.c;
        float f7 = cVar.d;
        float f8 = cVar.b;
        float f9 = cVar.c;
        float f10 = cVar.a;
        if (i == 3) {
            if (f10 < f6) {
                return true;
            }
        } else if (i == 4) {
            if (f9 > f5) {
                return true;
            }
        } else if (i == 5) {
            if (f8 < f4) {
                return true;
            }
        } else {
            if (i != 6) {
                throw new IllegalStateException("This function should only be used for 2-D focus search");
            }
            if (f7 > f3) {
                return true;
            }
        }
        if (i == 3 || i == 4) {
            return true;
        }
        if (i == 3) {
            f = f10 - cVar2.c;
        } else if (i == 4) {
            f = cVar2.a - f9;
        } else if (i == 5) {
            f = f8 - cVar2.d;
        } else {
            if (i != 6) {
                throw new IllegalStateException("This function should only be used for 2-D focus search");
            }
            f = cVar2.b - f7;
        }
        float fMax = Math.max(DefinitionKt.NO_Float_VALUE, f);
        if (i == 3) {
            f2 = f10 - f5;
        } else if (i == 4) {
            f2 = f6 - f9;
        } else if (i == 5) {
            f2 = f8 - f3;
        } else {
            if (i != 6) {
                throw new IllegalStateException("This function should only be used for 2-D focus search");
            }
            f2 = f4 - f7;
        }
        return fMax < Math.max(1.0f, f2);
    }

    public static final boolean c(int i, androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2) {
        if (i == 3 || i == 4) {
            return cVar.d > cVar2.b && cVar.b < cVar2.d;
        }
        if (i == 5 || i == 6) {
            return cVar.c > cVar2.a && cVar.a < cVar2.c;
        }
        throw new IllegalStateException("This function should only be used for 2-D focus search");
    }

    public static final androidx.compose.ui.geometry.c d(View view) {
        int[] iArr = a;
        view.getLocationInWindow(iArr);
        float f = iArr[0];
        return new androidx.compose.ui.geometry.c(f, iArr[1], view.getWidth() + f, iArr[1] + view.getHeight());
    }

    public static final boolean e(t tVar, boolean z) {
        int iOrdinal = tVar.N0().ordinal();
        s sVar = s.c;
        if (iOrdinal == 0) {
            tVar.R0(sVar);
            E(tVar);
            return true;
        }
        if (iOrdinal == 1) {
            t tVarP = p(tVar);
            if (!(tVarP != null ? e(tVarP, z) : true)) {
                return false;
            }
            tVar.R0(sVar);
            E(tVar);
            return true;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return true;
            }
            throw new NoWhenBranchMatchedException();
        }
        if (z) {
            tVar.R0(sVar);
            E(tVar);
        }
        return z;
    }

    public static final void f(t tVar, androidx.compose.runtime.collection.b bVar) {
        androidx.compose.ui.p pVar = tVar.a;
        if (!pVar.m) {
            throw new IllegalStateException("visitChildren called on an unattached node");
        }
        androidx.compose.runtime.collection.b bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
        androidx.compose.ui.p pVar2 = pVar.f;
        if (pVar2 == null) {
            AbstractC0910f.b(bVar2, pVar);
        } else {
            bVar2.b(pVar2);
        }
        while (bVar2.m()) {
            androidx.compose.ui.p pVarF = (androidx.compose.ui.p) bVar2.o(bVar2.c - 1);
            if ((pVarF.d & 1024) == 0) {
                AbstractC0910f.b(bVar2, pVarF);
            } else {
                while (true) {
                    if (pVarF == null) {
                        break;
                    }
                    if ((pVarF.c & 1024) != 0) {
                        androidx.compose.runtime.collection.b bVar3 = null;
                        while (pVarF != null) {
                            if (pVarF instanceof t) {
                                t tVar2 = (t) pVarF;
                                if (tVar2.m && !AbstractC0910f.v(tVar2).G) {
                                    if (tVar2.M0().a) {
                                        bVar.b(tVar2);
                                    } else {
                                        f(tVar2, bVar);
                                    }
                                }
                            } else if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                int i = 0;
                                for (androidx.compose.ui.p pVar3 = ((AbstractC0918n) pVarF).o; pVar3 != null; pVar3 = pVar3.f) {
                                    if ((pVar3.c & 1024) != 0) {
                                        i++;
                                        if (i == 1) {
                                            pVarF = pVar3;
                                        } else {
                                            if (bVar3 == null) {
                                                bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (pVarF != null) {
                                                bVar3.b(pVarF);
                                                pVarF = null;
                                            }
                                            bVar3.b(pVar3);
                                        }
                                    }
                                }
                                if (i == 1) {
                                }
                            }
                            pVarF = AbstractC0910f.f(bVar3);
                        }
                    } else {
                        pVarF = pVarF.f;
                    }
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:65:0x0036, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.t g(androidx.compose.ui.focus.t r8) {
        /*
            androidx.compose.ui.focus.s r0 = r8.N0()
            int r0 = r0.ordinal()
            if (r0 == 0) goto Lae
            r1 = 1
            r2 = 0
            if (r0 == r1) goto L1c
            r1 = 2
            if (r0 == r1) goto Lae
            r8 = 3
            if (r0 != r8) goto L16
            goto La5
        L16:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        L1c:
            androidx.compose.ui.p r8 = r8.a
            boolean r0 = r8.m
            if (r0 == 0) goto La6
            androidx.compose.runtime.collection.b r0 = new androidx.compose.runtime.collection.b
            r3 = 16
            androidx.compose.ui.p[] r4 = new androidx.compose.ui.p[r3]
            r0.<init>(r4)
            androidx.compose.ui.p r4 = r8.f
            if (r4 != 0) goto L33
            androidx.compose.ui.node.AbstractC0910f.b(r0, r8)
            goto L36
        L33:
            r0.b(r4)
        L36:
            boolean r8 = r0.m()
            if (r8 == 0) goto La5
            int r8 = r0.c
            int r8 = r8 - r1
            java.lang.Object r8 = r0.o(r8)
            androidx.compose.ui.p r8 = (androidx.compose.ui.p) r8
            int r4 = r8.d
            r4 = r4 & 1024(0x400, float:1.435E-42)
            if (r4 != 0) goto L4f
            androidx.compose.ui.node.AbstractC0910f.b(r0, r8)
            goto L36
        L4f:
            if (r8 == 0) goto L36
            int r4 = r8.c
            r4 = r4 & 1024(0x400, float:1.435E-42)
            if (r4 == 0) goto La2
            r4 = r2
        L58:
            if (r8 == 0) goto L36
            boolean r5 = r8 instanceof androidx.compose.ui.focus.t
            if (r5 == 0) goto L67
            androidx.compose.ui.focus.t r8 = (androidx.compose.ui.focus.t) r8
            androidx.compose.ui.focus.t r8 = g(r8)
            if (r8 == 0) goto L9d
            return r8
        L67:
            int r5 = r8.c
            r5 = r5 & 1024(0x400, float:1.435E-42)
            if (r5 == 0) goto L9d
            boolean r5 = r8 instanceof androidx.compose.ui.node.AbstractC0918n
            if (r5 == 0) goto L9d
            r5 = r8
            androidx.compose.ui.node.n r5 = (androidx.compose.ui.node.AbstractC0918n) r5
            androidx.compose.ui.p r5 = r5.o
            r6 = 0
        L77:
            if (r5 == 0) goto L9a
            int r7 = r5.c
            r7 = r7 & 1024(0x400, float:1.435E-42)
            if (r7 == 0) goto L97
            int r6 = r6 + 1
            if (r6 != r1) goto L85
            r8 = r5
            goto L97
        L85:
            if (r4 != 0) goto L8e
            androidx.compose.runtime.collection.b r4 = new androidx.compose.runtime.collection.b
            androidx.compose.ui.p[] r7 = new androidx.compose.ui.p[r3]
            r4.<init>(r7)
        L8e:
            if (r8 == 0) goto L94
            r4.b(r8)
            r8 = r2
        L94:
            r4.b(r5)
        L97:
            androidx.compose.ui.p r5 = r5.f
            goto L77
        L9a:
            if (r6 != r1) goto L9d
            goto L58
        L9d:
            androidx.compose.ui.p r8 = androidx.compose.ui.node.AbstractC0910f.f(r4)
            goto L58
        La2:
            androidx.compose.ui.p r8 = r8.f
            goto L4f
        La5:
            return r2
        La6:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "visitChildren called on an unattached node"
            r8.<init>(r0)
            throw r8
        Lae:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.g(androidx.compose.ui.focus.t):androidx.compose.ui.focus.t");
    }

    public static final t h(androidx.compose.runtime.collection.b bVar, androidx.compose.ui.geometry.c cVar, int i) {
        androidx.compose.ui.geometry.c cVarI;
        if (i == 3) {
            cVarI = cVar.i(cVar.e() + 1, DefinitionKt.NO_Float_VALUE);
        } else if (i == 4) {
            cVarI = cVar.i(-(cVar.e() + 1), DefinitionKt.NO_Float_VALUE);
        } else if (i == 5) {
            cVarI = cVar.i(DefinitionKt.NO_Float_VALUE, cVar.d() + 1);
        } else {
            if (i != 6) {
                throw new IllegalStateException("This function should only be used for 2-D focus search");
            }
            cVarI = cVar.i(DefinitionKt.NO_Float_VALUE, -(cVar.d() + 1));
        }
        int i2 = bVar.c;
        t tVar = null;
        if (i2 > 0) {
            Object[] objArr = bVar.a;
            int i3 = 0;
            do {
                t tVar2 = (t) objArr[i3];
                if (v(tVar2)) {
                    androidx.compose.ui.geometry.c cVarJ = j(tVar2);
                    if (t(i, cVarJ, cVar) && (!t(i, cVarI, cVar) || b(cVar, cVarJ, cVarI, i) || (!b(cVar, cVarI, cVarJ, i) && u(i, cVar, cVarJ) < u(i, cVar, cVarI)))) {
                        tVar = tVar2;
                        cVarI = cVarJ;
                    }
                }
                i3++;
            } while (i3 < i2);
        }
        return tVar;
    }

    public static final boolean i(t tVar, int i, Function1 function1) {
        androidx.compose.ui.geometry.c cVar;
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new t[16]);
        f(tVar, bVar);
        if (bVar.c <= 1) {
            t tVar2 = (t) (bVar.l() ? null : bVar.a[0]);
            if (tVar2 != null) {
                return ((Boolean) function1.invoke(tVar2)).booleanValue();
            }
        } else {
            if (i == 7) {
                i = 4;
            }
            if (i == 4 || i == 6) {
                androidx.compose.ui.geometry.c cVarJ = j(tVar);
                float f = cVarJ.b;
                float f2 = cVarJ.a;
                cVar = new androidx.compose.ui.geometry.c(f2, f, f2, f);
            } else {
                if (i != 3 && i != 5) {
                    throw new IllegalStateException("This function should only be used for 2-D focus search");
                }
                androidx.compose.ui.geometry.c cVarJ2 = j(tVar);
                float f3 = cVarJ2.d;
                float f4 = cVarJ2.c;
                cVar = new androidx.compose.ui.geometry.c(f4, f3, f4, f3);
            }
            t tVarH = h(bVar, cVar, i);
            if (tVarH != null) {
                return ((Boolean) function1.invoke(tVarH)).booleanValue();
            }
        }
        return false;
    }

    public static final androidx.compose.ui.geometry.c j(t tVar) {
        a0 a0Var = tVar.h;
        return a0Var != null ? AbstractC0897s.g(a0Var).o(a0Var, false) : androidx.compose.ui.geometry.c.e;
    }

    public static final androidx.compose.ui.q k(androidx.compose.ui.q qVar, p pVar) {
        return qVar.g(new FocusRequesterElement(pVar));
    }

    public static final boolean l(t tVar, androidx.activity.compose.g gVar) {
        int iOrdinal = tVar.N0().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                t tVarP = p(tVar);
                if (tVarP != null) {
                    return l(tVarP, gVar) || o(tVar, tVarP, 1, gVar);
                }
                throw new IllegalStateException("ActiveParent must have a focusedChild");
            }
            if (iOrdinal != 2) {
                if (iOrdinal == 3) {
                    return tVar.M0().a ? ((Boolean) gVar.invoke(tVar)).booleanValue() : D(tVar, gVar);
                }
                throw new NoWhenBranchMatchedException();
            }
        }
        return D(tVar, gVar);
    }

    public static final boolean m(t tVar) {
        com.bumptech.glide.manager.p pVarI = I(tVar);
        try {
            if (pVarI.a) {
                com.bumptech.glide.manager.p.a(pVarI);
            }
            boolean z = true;
            pVarI.a = true;
            int iOrdinal = tVar.N0().ordinal();
            if (iOrdinal != 0) {
                if (iOrdinal == 1) {
                    z = false;
                } else if (iOrdinal == 2) {
                    tVar.R0(s.a);
                    E(tVar);
                } else {
                    if (iOrdinal != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    z = false;
                }
            }
            com.bumptech.glide.manager.p.d(pVarI);
            return z;
        } catch (Throwable th) {
            com.bumptech.glide.manager.p.d(pVarI);
            throw th;
        }
    }

    public static final boolean n(int i, androidx.activity.compose.g gVar, t tVar, androidx.compose.ui.geometry.c cVar) {
        if (K(i, gVar, tVar, cVar)) {
            return true;
        }
        Boolean bool = (Boolean) J(tVar, i, new X(tVar, cVar, i, gVar, 5));
        if (bool != null) {
            return bool.booleanValue();
        }
        return false;
    }

    public static final boolean o(t tVar, t tVar2, int i, androidx.activity.compose.g gVar) {
        if (L(tVar, tVar2, i, gVar)) {
            return true;
        }
        Boolean bool = (Boolean) J(tVar, i, new X(tVar, tVar2, i, gVar, 4));
        if (bool != null) {
            return bool.booleanValue();
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:63:0x001f, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.t p(androidx.compose.ui.focus.t r8) {
        /*
            androidx.compose.ui.p r8 = r8.a
            boolean r0 = r8.m
            r1 = 0
            if (r0 != 0) goto L9
            goto L9f
        L9:
            if (r0 == 0) goto La0
            androidx.compose.runtime.collection.b r0 = new androidx.compose.runtime.collection.b
            r2 = 16
            androidx.compose.ui.p[] r3 = new androidx.compose.ui.p[r2]
            r0.<init>(r3)
            androidx.compose.ui.p r3 = r8.f
            if (r3 != 0) goto L1c
            androidx.compose.ui.node.AbstractC0910f.b(r0, r8)
            goto L1f
        L1c:
            r0.b(r3)
        L1f:
            boolean r8 = r0.m()
            if (r8 == 0) goto L9f
            int r8 = r0.c
            r3 = 1
            int r8 = r8 - r3
            java.lang.Object r8 = r0.o(r8)
            androidx.compose.ui.p r8 = (androidx.compose.ui.p) r8
            int r4 = r8.d
            r4 = r4 & 1024(0x400, float:1.435E-42)
            if (r4 != 0) goto L39
            androidx.compose.ui.node.AbstractC0910f.b(r0, r8)
            goto L1f
        L39:
            if (r8 == 0) goto L1f
            int r4 = r8.c
            r4 = r4 & 1024(0x400, float:1.435E-42)
            if (r4 == 0) goto L9c
            r4 = r1
        L42:
            if (r8 == 0) goto L1f
            boolean r5 = r8 instanceof androidx.compose.ui.focus.t
            if (r5 == 0) goto L61
            androidx.compose.ui.focus.t r8 = (androidx.compose.ui.focus.t) r8
            androidx.compose.ui.p r5 = r8.a
            boolean r5 = r5.m
            if (r5 == 0) goto L97
            androidx.compose.ui.focus.s r5 = r8.N0()
            int r5 = r5.ordinal()
            if (r5 == 0) goto L60
            if (r5 == r3) goto L60
            r6 = 2
            if (r5 == r6) goto L60
            goto L97
        L60:
            return r8
        L61:
            int r5 = r8.c
            r5 = r5 & 1024(0x400, float:1.435E-42)
            if (r5 == 0) goto L97
            boolean r5 = r8 instanceof androidx.compose.ui.node.AbstractC0918n
            if (r5 == 0) goto L97
            r5 = r8
            androidx.compose.ui.node.n r5 = (androidx.compose.ui.node.AbstractC0918n) r5
            androidx.compose.ui.p r5 = r5.o
            r6 = 0
        L71:
            if (r5 == 0) goto L94
            int r7 = r5.c
            r7 = r7 & 1024(0x400, float:1.435E-42)
            if (r7 == 0) goto L91
            int r6 = r6 + 1
            if (r6 != r3) goto L7f
            r8 = r5
            goto L91
        L7f:
            if (r4 != 0) goto L88
            androidx.compose.runtime.collection.b r4 = new androidx.compose.runtime.collection.b
            androidx.compose.ui.p[] r7 = new androidx.compose.ui.p[r2]
            r4.<init>(r7)
        L88:
            if (r8 == 0) goto L8e
            r4.b(r8)
            r8 = r1
        L8e:
            r4.b(r5)
        L91:
            androidx.compose.ui.p r5 = r5.f
            goto L71
        L94:
            if (r6 != r3) goto L97
            goto L42
        L97:
            androidx.compose.ui.p r8 = androidx.compose.ui.node.AbstractC0910f.f(r4)
            goto L42
        L9c:
            androidx.compose.ui.p r8 = r8.f
            goto L39
        L9f:
            return r1
        La0:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "visitChildren called on an unattached node"
            r8.<init>(r0)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.p(androidx.compose.ui.focus.t):androidx.compose.ui.focus.t");
    }

    /* JADX WARN: Code restructure failed: missing block: B:105:0x0075, code lost:
    
        continue;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.compose.ui.focus.s q(androidx.compose.ui.focus.d r10) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.q(androidx.compose.ui.focus.d):androidx.compose.ui.focus.s");
    }

    public static final void r(t tVar) {
        AbstractC0910f.s(tVar, new u(tVar, 0));
        int iOrdinal = tVar.N0().ordinal();
        if (iOrdinal == 1 || iOrdinal == 3) {
            tVar.R0(s.a);
        }
    }

    public static final void s(t tVar) {
        f fVar = ((j) ((C0971v) AbstractC0910f.w(tVar)).getFocusOwner()).g;
        fVar.b(fVar.c, tVar);
    }

    public static final boolean t(int i, androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2) {
        float f = cVar.a;
        float f2 = cVar.c;
        if (i == 3) {
            float f3 = cVar2.c;
            float f4 = cVar2.a;
            return (f3 > f2 || f4 >= f2) && f4 > f;
        }
        if (i == 4) {
            float f5 = cVar2.a;
            float f6 = cVar2.c;
            return (f5 < f || f6 <= f) && f6 < f2;
        }
        float f7 = cVar.b;
        float f8 = cVar.d;
        if (i == 5) {
            float f9 = cVar2.d;
            float f10 = cVar2.b;
            return (f9 > f8 || f10 >= f8) && f10 > f7;
        }
        if (i != 6) {
            throw new IllegalStateException("This function should only be used for 2-D focus search");
        }
        float f11 = cVar2.b;
        float f12 = cVar2.d;
        return (f11 < f7 || f12 <= f7) && f12 < f8;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0036  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final long u(int r10, androidx.compose.ui.geometry.c r11, androidx.compose.ui.geometry.c r12) {
        /*
            float r0 = r12.b
            float r1 = r12.a
            java.lang.String r2 = "This function should only be used for 2-D focus search"
            r3 = 6
            r4 = 5
            r5 = 4
            r6 = 3
            if (r10 != r6) goto L12
            float r7 = r11.a
            float r8 = r12.c
        L10:
            float r7 = r7 - r8
            goto L26
        L12:
            if (r10 != r5) goto L19
            float r7 = r11.c
            float r7 = r1 - r7
            goto L26
        L19:
            if (r10 != r4) goto L20
            float r7 = r11.b
            float r8 = r12.d
            goto L10
        L20:
            if (r10 != r3) goto L6f
            float r7 = r11.d
            float r7 = r0 - r7
        L26:
            r8 = 0
            float r7 = java.lang.Math.max(r8, r7)
            float r7 = java.lang.Math.abs(r7)
            long r7 = (long) r7
            r9 = 2
            if (r10 != r6) goto L34
            goto L36
        L34:
            if (r10 != r5) goto L47
        L36:
            float r10 = r11.d()
            float r1 = (float) r9
            float r10 = r10 / r1
            float r11 = r11.b
            float r10 = r10 + r11
            float r11 = r12.d()
            float r11 = r11 / r1
            float r11 = r11 + r0
        L45:
            float r10 = r10 - r11
            goto L5c
        L47:
            if (r10 != r4) goto L4a
            goto L4c
        L4a:
            if (r10 != r3) goto L69
        L4c:
            float r10 = r11.e()
            float r0 = (float) r9
            float r10 = r10 / r0
            float r11 = r11.a
            float r10 = r10 + r11
            float r11 = r12.e()
            float r11 = r11 / r0
            float r11 = r11 + r1
            goto L45
        L5c:
            float r10 = java.lang.Math.abs(r10)
            long r10 = (long) r10
            r12 = 13
            long r0 = (long) r12
            long r0 = r0 * r7
            long r0 = r0 * r7
            long r10 = r10 * r10
            long r10 = r10 + r0
            return r10
        L69:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            r10.<init>(r2)
            throw r10
        L6f:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            r10.<init>(r2)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.a.u(int, androidx.compose.ui.geometry.c, androidx.compose.ui.geometry.c):long");
    }

    public static final boolean v(t tVar) {
        E e;
        a0 a0Var;
        E e2;
        a0 a0Var2 = tVar.h;
        return (a0Var2 == null || (e = a0Var2.l) == null || !e.F() || (a0Var = tVar.h) == null || (e2 = a0Var.l) == null || !e2.E()) ? false : true;
    }

    public static final androidx.compose.ui.q w(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new FocusChangedElement(function1));
    }

    public static final androidx.compose.ui.q x(androidx.compose.ui.q qVar, Function1 function1) {
        return qVar.g(new FocusEventElement(function1));
    }

    /* JADX WARN: Type inference failed for: r0v7, types: [java.lang.Object, kotlin.jvm.functions.Function1] */
    public static final int y(t tVar, int i) {
        int iOrdinal = tVar.N0().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                t tVarP = p(tVar);
                if (tVarP == null) {
                    throw new IllegalArgumentException("ActiveParent with no focused child");
                }
                int iY = y(tVarP, i);
                if (iY == 1) {
                    iY = 0;
                }
                if (iY != 0) {
                    return iY;
                }
                if (!tVar.n) {
                    tVar.n = true;
                    try {
                        p pVar = (p) tVar.M0().k.invoke(new c(i));
                        if (pVar == p.b) {
                            return 1;
                        }
                        if (pVar == p.c) {
                            return 2;
                        }
                        return pVar.a(i.e) ? 3 : 4;
                    } finally {
                        tVar.n = false;
                    }
                }
            } else {
                if (iOrdinal == 2) {
                    return 2;
                }
                if (iOrdinal != 3) {
                    throw new NoWhenBranchMatchedException();
                }
            }
        }
        return 1;
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, kotlin.jvm.functions.Function1] */
    public static final int z(t tVar, int i) {
        if (!tVar.o) {
            tVar.o = true;
            try {
                p pVar = (p) tVar.M0().j.invoke(new c(i));
                if (pVar != p.b) {
                    if (pVar != p.c) {
                        return pVar.a(i.e) ? 3 : 4;
                    }
                    tVar.o = false;
                    return 2;
                }
            } finally {
                tVar.o = false;
            }
        }
        return 1;
    }
}

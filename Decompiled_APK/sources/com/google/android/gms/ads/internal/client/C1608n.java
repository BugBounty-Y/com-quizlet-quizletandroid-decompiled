package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.Bundle;
import android.text.Layout;
import android.text.TextUtils;
import androidx.camera.core.C0196t;
import androidx.camera.core.impl.C0166e;
import androidx.navigation.compose.C1277j;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2359mg;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1777Te;
import com.google.android.gms.internal.ads.C2147hi;
import com.google.android.gms.internal.ads.C2368mp;
import com.google.android.gms.internal.ads.C2454op;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2728v5;
import com.google.android.gms.internal.ads.C2754vp;
import com.google.android.gms.internal.ads.Gp;
import com.google.android.gms.internal.ads.Lh;
import com.google.android.gms.internal.ads.Pg;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.Rn;
import com.google.android.gms.internal.ads.RunnableC2793wl;
import com.google.android.gms.internal.ads.Sg;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Ts;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Zg;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.gtm.zzen;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3435c3;
import com.quizlet.db.data.caches.UserInfoCache;
import java.io.File;
import java.text.Bidi;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.ads.internal.client.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1608n implements Pg, Pv {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;

    public C1608n(C2728v5 c2728v5, File file, File file2, File file3) {
        this.a = c2728v5;
        this.b = file;
        this.c = file3;
        this.d = file2;
    }

    public static void y(Context context, String str) {
        Bundle bundle = new Bundle();
        bundle.putString("action", "no_ads_fallback");
        bundle.putString("flow", str);
        C1614q c1614q = C1614q.f;
        com.google.android.gms.ads.internal.util.client.c cVar = c1614q.a;
        String str2 = c1614q.d.a;
        cVar.getClass();
        com.google.android.gms.ads.internal.util.client.c.m(context, str2, bundle, new com.google.android.gms.internal.mlkit_common.u(cVar));
    }

    @Override // com.google.android.gms.internal.ads.Pg
    public /* synthetic */ Pg a(C2754vp c2754vp) {
        this.c = c2754vp;
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pg
    public /* synthetic */ Pg b(Gp gp) {
        this.b = gp;
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Tq tq;
        AbstractC2359mg abstractC2359mg = (AbstractC2359mg) obj;
        C2454op c2454op = (C2454op) this.e;
        synchronized (c2454op) {
            try {
                c2454op.j = null;
                if (((Boolean) r.d.c.a(AbstractC2773w7.h8)).booleanValue()) {
                    ((Lh) abstractC2359mg.g.a.b).d = c2454op.d;
                }
                ((Rn) this.a).o(abstractC2359mg);
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = c2454op.h;
                    Pq pq = (Pq) this.c;
                    pq.f(abstractC2359mg.a.b);
                    pq.I(abstractC2359mg.f.a);
                    pq.h(true);
                    uq.b(pq.l());
                } else {
                    tq.g(abstractC2359mg.a.b);
                    tq.e(abstractC2359mg.f.a);
                    Pq pq2 = (Pq) this.c;
                    pq2.h(true);
                    tq.a(pq2);
                    tq.h();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void d(coil3.fetch.f fVar, C4950i c4950i) {
        ((ArrayList) this.d).add(new C1277j(1, fVar, c4950i));
    }

    public void e(coil3.map.a aVar, C4950i c4950i) {
        ((ArrayList) this.b).add(new Pair(aVar, c4950i));
    }

    public void f(com.google.android.gms.analytics.ecommerce.a aVar, String str) {
        if (aVar == null) {
            zzen.zze("product should be non-null");
            return;
        }
        if (str == null) {
            str = "";
        }
        HashMap map = (HashMap) this.c;
        if (!map.containsKey(str)) {
            map.put(str, new ArrayList());
        }
        ((List) map.get(str)).add(aVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0076  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.text.Bidi h(int r14) {
        /*
            r13 = this;
            java.lang.Object r0 = r13.d
            boolean[] r0 = (boolean[]) r0
            boolean r1 = r0[r14]
            java.lang.Object r2 = r13.c
            java.util.ArrayList r2 = (java.util.ArrayList) r2
            if (r1 == 0) goto L13
            java.lang.Object r14 = r2.get(r14)
            java.text.Bidi r14 = (java.text.Bidi) r14
            return r14
        L13:
            java.lang.Object r1 = r13.b
            java.util.ArrayList r1 = (java.util.ArrayList) r1
            r3 = 0
            if (r14 != 0) goto L1c
            r4 = r3
            goto L28
        L1c:
            int r4 = r14 + (-1)
            java.lang.Object r4 = r1.get(r4)
            java.lang.Number r4 = (java.lang.Number) r4
            int r4 = r4.intValue()
        L28:
            java.lang.Object r1 = r1.get(r14)
            java.lang.Number r1 = (java.lang.Number) r1
            int r1 = r1.intValue()
            int r10 = r1 - r4
            java.lang.Object r5 = r13.e
            char[] r5 = (char[]) r5
            if (r5 == 0) goto L40
            int r6 = r5.length
            if (r6 >= r10) goto L3e
            goto L40
        L3e:
            r6 = r5
            goto L43
        L40:
            char[] r5 = new char[r10]
            goto L3e
        L43:
            java.lang.Object r5 = r13.a
            android.text.Layout r5 = (android.text.Layout) r5
            java.lang.CharSequence r7 = r5.getText()
            android.text.TextUtils.getChars(r7, r4, r1, r6, r3)
            boolean r1 = java.text.Bidi.requiresBidi(r6, r3, r10)
            r4 = 1
            r12 = 0
            if (r1 == 0) goto L76
            int r1 = r13.o(r14)
            int r1 = r5.getLineForOffset(r1)
            int r1 = r5.getParagraphDirection(r1)
            r5 = -1
            if (r1 != r5) goto L67
            r11 = r4
            goto L68
        L67:
            r11 = r3
        L68:
            java.text.Bidi r5 = new java.text.Bidi
            r9 = 0
            r7 = 0
            r8 = 0
            r5.<init>(r6, r7, r8, r9, r10, r11)
            int r1 = r5.getRunCount()
            if (r1 != r4) goto L77
        L76:
            r5 = r12
        L77:
            r2.set(r14, r5)
            r0[r14] = r4
            if (r5 == 0) goto L87
            java.lang.Object r14 = r13.e
            char[] r14 = (char[]) r14
            if (r6 != r14) goto L86
            r6 = r12
            goto L87
        L86:
            r6 = r14
        L87:
            r13.e = r6
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.h(int):java.text.Bidi");
    }

    public C0166e i() {
        String strK = ((androidx.camera.core.impl.J) this.a) == null ? " surface" : "";
        if (((List) this.b) == null) {
            strK = strK.concat(" sharedSurfaces");
        }
        if (((Integer) this.c) == null) {
            strK = android.support.v4.media.session.a.k(strK, " mirrorMode");
        }
        if (((Integer) this.d) == null) {
            strK = android.support.v4.media.session.a.k(strK, " surfaceGroupId");
        }
        if (((C0196t) this.e) == null) {
            strK = android.support.v4.media.session.a.k(strK, " dynamicRange");
        }
        if (strK.isEmpty()) {
            return new C0166e((androidx.camera.core.impl.J) this.a, (List) this.b, ((Integer) this.c).intValue(), ((Integer) this.d).intValue(), (C0196t) this.e);
        }
        throw new IllegalStateException("Missing required properties:".concat(strK));
    }

    public HashMap j() {
        HashMap map = new HashMap((HashMap) this.a);
        com.quizlet.data.repository.school.membership.a aVar = (com.quizlet.data.repository.school.membership.a) this.b;
        if (aVar != null) {
            map.putAll(new HashMap((HashMap) aVar.b));
        }
        Iterator it2 = ((ArrayList) this.d).iterator();
        int i = 1;
        while (it2.hasNext()) {
            com.google.android.gms.analytics.ecommerce.b bVar = (com.google.android.gms.analytics.ecommerce.b) it2.next();
            String strC = AbstractC3435c3.c(i, "&promo");
            bVar.getClass();
            HashMap map2 = new HashMap();
            for (Map.Entry entry : bVar.a.entrySet()) {
                map2.put(strC.concat(String.valueOf((String) entry.getKey())), (String) entry.getValue());
            }
            map.putAll(map2);
            i++;
        }
        Iterator it3 = ((ArrayList) this.e).iterator();
        int i2 = 1;
        while (it3.hasNext()) {
            map.putAll(((com.google.android.gms.analytics.ecommerce.a) it3.next()).a(AbstractC3435c3.c(i2, "&pr")));
            i2++;
        }
        int i3 = 1;
        for (Map.Entry entry2 : ((HashMap) this.c).entrySet()) {
            List list = (List) entry2.getValue();
            String strC2 = AbstractC3435c3.c(i3, "&il");
            Iterator it4 = list.iterator();
            int i4 = 1;
            while (it4.hasNext()) {
                map.putAll(((com.google.android.gms.analytics.ecommerce.a) it4.next()).a(strC2.concat(AbstractC3435c3.c(i4, "pi"))));
                i4++;
            }
            if (!TextUtils.isEmpty((CharSequence) entry2.getKey())) {
                map.put(strC2.concat("nm"), (String) entry2.getKey());
            }
            i3++;
        }
        return map;
    }

    public float k(int i, boolean z) {
        Layout layout = (Layout) this.a;
        int lineEnd = layout.getLineEnd(layout.getLineForOffset(i));
        if (i > lineEnd) {
            i = lineEnd;
        }
        return z ? layout.getPrimaryHorizontal(i) : layout.getSecondaryHorizontal(i);
    }

    public ArrayList l() {
        ArrayList arrayList = (ArrayList) this.b;
        if (arrayList == null) {
            throw new IllegalStateException("Generate a test before attempting to grade it");
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((test.utils.a) it2.next()).b);
        }
        return arrayList2;
    }

    public float m(int i, boolean z, boolean z2) {
        int i2;
        int i3;
        int iS = i;
        if (!z2) {
            return k(i, z);
        }
        Layout layout = (Layout) this.a;
        int iC = androidx.compose.ui.text.android.s.c(layout, iS, z2);
        int lineStart = layout.getLineStart(iC);
        int lineEnd = layout.getLineEnd(iC);
        if (iS != lineStart && iS != lineEnd) {
            return k(i, z);
        }
        if (iS == 0 || iS == layout.getText().length()) {
            return k(i, z);
        }
        int iN = n(iS, z2);
        boolean z3 = layout.getParagraphDirection(layout.getLineForOffset(o(iN))) == -1;
        int iS2 = s(lineEnd, lineStart);
        int iO = o(iN);
        int i4 = lineStart - iO;
        int i5 = iS2 - iO;
        Bidi bidiH = h(iN);
        Bidi bidiCreateLineBidi = bidiH != null ? bidiH.createLineBidi(i4, i5) : null;
        if (bidiCreateLineBidi == null || bidiCreateLineBidi.getRunCount() == 1) {
            boolean zIsRtlCharAt = layout.isRtlCharAt(lineStart);
            if (z || z3 == zIsRtlCharAt) {
                z3 = !z3;
            }
            return iS == lineStart ? z3 : !z3 ? layout.getLineLeft(iC) : layout.getLineRight(iC);
        }
        int runCount = bidiCreateLineBidi.getRunCount();
        androidx.compose.ui.text.android.l[] lVarArr = new androidx.compose.ui.text.android.l[runCount];
        for (int i6 = 0; i6 < runCount; i6++) {
            lVarArr[i6] = new androidx.compose.ui.text.android.l(bidiCreateLineBidi.getRunStart(i6) + lineStart, bidiCreateLineBidi.getRunLimit(i6) + lineStart, bidiCreateLineBidi.getRunLevel(i6) % 2 == 1);
        }
        int runCount2 = bidiCreateLineBidi.getRunCount();
        byte[] bArr = new byte[runCount2];
        for (int i7 = 0; i7 < runCount2; i7++) {
            bArr[i7] = (byte) bidiCreateLineBidi.getRunLevel(i7);
        }
        Bidi.reorderVisually(bArr, 0, lVarArr, 0, runCount);
        if (iS == lineStart) {
            int i8 = 0;
            while (true) {
                if (i8 >= runCount) {
                    i3 = -1;
                    break;
                }
                if (lVarArr[i8].a == iS) {
                    i3 = i8;
                    break;
                }
                i8++;
            }
            boolean z4 = (z || z3 == lVarArr[i3].c) ? !z3 : z3;
            if (i3 == 0 && z4) {
                return layout.getLineLeft(iC);
            }
            Intrinsics.checkNotNullParameter(lVarArr, "<this>");
            return (i3 != runCount - 1 || z4) ? z4 ? layout.getPrimaryHorizontal(lVarArr[i3 - 1].a) : layout.getPrimaryHorizontal(lVarArr[i3 + 1].a) : layout.getLineRight(iC);
        }
        if (iS > iS2) {
            iS = s(iS, lineStart);
        }
        int i9 = 0;
        while (true) {
            if (i9 >= runCount) {
                i2 = -1;
                break;
            }
            if (lVarArr[i9].b == iS) {
                i2 = i9;
                break;
            }
            i9++;
        }
        boolean z5 = (z || z3 == lVarArr[i2].c) ? z3 : !z3;
        if (i2 == 0 && z5) {
            return layout.getLineLeft(iC);
        }
        Intrinsics.checkNotNullParameter(lVarArr, "<this>");
        return (i2 != runCount - 1 || z5) ? z5 ? layout.getPrimaryHorizontal(lVarArr[i2 - 1].b) : layout.getPrimaryHorizontal(lVarArr[i2 + 1].b) : layout.getLineRight(iC);
    }

    public int n(int i, boolean z) {
        ArrayList arrayList = (ArrayList) this.b;
        int iG = kotlin.collections.B.g(arrayList, Integer.valueOf(i));
        int i2 = iG < 0 ? -(iG + 1) : iG + 1;
        if (z && i2 > 0) {
            int i3 = i2 - 1;
            if (i == ((Number) arrayList.get(i3)).intValue()) {
                return i3;
            }
        }
        return i2;
    }

    public int o(int i) {
        if (i == 0) {
            return 0;
        }
        return ((Number) ((ArrayList) this.b).get(i - 1)).intValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(com.quizlet.features.folders.viewmodel.usecases.c r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.folders.viewmodel.usecases.f
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.folders.viewmodel.usecases.f r0 = (com.quizlet.features.folders.viewmodel.usecases.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.f r0 = new com.quizlet.features.folders.viewmodel.usecases.f
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L58
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.String r5 = r5.d
            if (r5 == 0) goto L61
            boolean r5 = kotlin.text.StringsKt.O(r5)
            if (r5 == 0) goto L3d
            goto L61
        L3d:
            java.lang.Object r5 = r4.a
            com.quizlet.db.data.caches.UserInfoCache r5 = (com.quizlet.db.data.caches.UserInfoCache) r5
            boolean r5 = r5.b()
            if (r5 == 0) goto L61
            java.lang.Object r5 = r4.b
            androidx.work.impl.model.c r5 = (androidx.work.impl.model.c) r5
            io.reactivex.rxjava3.internal.operators.single.g r5 = r5.u()
            r0.l = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r6 != r1) goto L58
            return r1
        L58:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r5 = r6.booleanValue()
            if (r5 != 0) goto L61
            goto L62
        L61:
            r3 = 0
        L62:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.p(com.quizlet.features.folders.viewmodel.usecases.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(java.util.ArrayList r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof test.utils.d
            if (r0 == 0) goto L13
            r0 = r9
            test.utils.d r0 = (test.utils.d) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            test.utils.d r0 = new test.utils.d
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L34
            if (r2 != r4) goto L2c
            int r8 = r0.k
            com.google.android.gms.ads.internal.client.n r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5e
        L2c:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r7.d
            assistantMode.types.test.GradedTestResult r9 = (assistantMode.types.test.GradedTestResult) r9
            if (r9 == 0) goto L3f
            r9 = r4
            goto L40
        L3f:
            r9 = r3
        L40:
            java.util.ArrayList r2 = r7.l()
            com.quizlet.local.ormlite.models.term.b r5 = new com.quizlet.local.ormlite.models.term.b
            r5.<init>(r2)
            r0.j = r7
            r0.k = r9
            r0.n = r4
            java.lang.Object r2 = r7.a
            assistantMode.refactored.types.AssistantGradingSettings r2 = (assistantMode.refactored.types.AssistantGradingSettings) r2
            java.lang.Object r8 = r5.g(r8, r2, r0)
            if (r8 != r1) goto L5a
            return r1
        L5a:
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r7
        L5e:
            test.utils.g r9 = (test.utils.g) r9
            assistantMode.types.test.GradedTestResult r1 = new assistantMode.types.test.GradedTestResult
            double r5 = r9.a
            assistantMode.types.TestGeneratorOutputMetadata r2 = new assistantMode.types.TestGeneratorOutputMetadata
            if (r8 == 0) goto L69
            r3 = r4
        L69:
            r8 = 6
            r2.<init>(r3, r8)
            java.util.ArrayList r8 = r9.b
            r1.<init>(r5, r8, r2)
            r0.d = r1
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.q(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object r(java.util.ArrayList r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof test.utils.e
            if (r0 == 0) goto L13
            r0 = r7
            test.utils.e r0 = (test.utils.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            test.utils.e r0 = new test.utils.e
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            metering.manager.a r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L46
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r5.e
            metering.manager.a r7 = (metering.manager.a) r7
            r0.j = r7
            r0.m = r3
            java.lang.Object r6 = r5.q(r6, r0)
            if (r6 != r1) goto L43
            return r1
        L43:
            r4 = r7
            r7 = r6
            r6 = r4
        L46:
            assistantMode.types.test.a r7 = (assistantMode.types.test.a) r7
            assistantMode.types.test.a r6 = r6.T(r7)
            boolean r7 = r6 instanceof assistantMode.types.test.GradedTestResult
            if (r7 == 0) goto L51
            return r6
        L51:
            java.lang.Class<assistantMode.types.test.GradedTestResult> r7 = assistantMode.types.test.GradedTestResult.class
            kotlin.jvm.internal.i r7 = kotlin.jvm.internal.K.a(r7)
            java.lang.Class r6 = r6.getClass()
            kotlin.jvm.internal.i r6 = kotlin.jvm.internal.K.a(r6)
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Expected output type "
            r0.<init>(r1)
            r0.append(r7)
            java.lang.String r7 = ", but got "
            r0.append(r7)
            r0.append(r6)
            java.lang.String r6 = r0.toString()
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r6 = r6.toString()
            r7.<init>(r6)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.r(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public int s(int i, int i2) {
        while (i > i2) {
            char cCharAt = ((Layout) this.a).getText().charAt(i - 1);
            if (cCharAt != ' ' && cCharAt != '\n' && cCharAt != 5760 && ((Intrinsics.g(cCharAt, 8192) < 0 || Intrinsics.g(cCharAt, 8202) > 0 || cCharAt == 8199) && cCharAt != 8287 && cCharAt != 12288)) {
                return i;
            }
            i--;
        }
        return i;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable t(long r6, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            r0 = 1
            boolean r1 = r8 instanceof com.quizlet.features.folders.viewmodel.usecases.g
            if (r1 == 0) goto L14
            r1 = r8
            com.quizlet.features.folders.viewmodel.usecases.g r1 = (com.quizlet.features.folders.viewmodel.usecases.g) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L14
            int r2 = r2 - r3
            r1.n = r2
            goto L19
        L14:
            com.quizlet.features.folders.viewmodel.usecases.g r1 = new com.quizlet.features.folders.viewmodel.usecases.g
            r1.<init>(r5, r8)
        L19:
            java.lang.Object r8 = r1.l
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.n
            if (r3 == 0) goto L33
            if (r3 != r0) goto L2b
            long r6 = r1.k
            com.google.android.gms.ads.internal.client.n r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L48
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r1.j = r5
            r1.k = r6
            r1.n = r0
            java.lang.Object r8 = r5.c
            com.google.firebase.crashlytics.internal.settings.b r8 = (com.google.firebase.crashlytics.internal.settings.b) r8
            java.lang.Object r8 = r8.h(r1)
            if (r8 != r2) goto L47
            return r2
        L47:
            r1 = r5
        L48:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            java.lang.Object r1 = r1.a
            com.quizlet.db.data.caches.UserInfoCache r1 = (com.quizlet.db.data.caches.UserInfoCache) r1
            long r1 = r1.getPersonId()
            int r6 = (r6 > r1 ? 1 : (r6 == r1 ? 0 : -1))
            if (r6 != 0) goto L6d
            com.quizlet.features.folders.menu.c[] r6 = new com.quizlet.features.folders.menu.c[r0]
            com.quizlet.features.folders.menu.a r7 = com.quizlet.features.folders.menu.a.a
            r0 = 0
            r6[r0] = r7
            java.util.ArrayList r6 = kotlin.collections.B.k(r6)
            if (r8 == 0) goto L6c
            com.quizlet.features.folders.menu.b r7 = com.quizlet.features.folders.menu.b.a
            r6.add(r7)
        L6c:
            return r6
        L6d:
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.t(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00aa A[Catch: Exception -> 0x00fd, TryCatch #0 {Exception -> 0x00fd, blocks: (B:13:0x0033, B:35:0x00a2, B:37:0x00aa, B:39:0x00c3, B:41:0x00c8, B:45:0x00ce, B:40:0x00c6, B:46:0x00d6, B:49:0x00e4, B:51:0x00f7, B:18:0x0046, B:29:0x0074, B:31:0x0081, B:21:0x0050, B:25:0x0061), top: B:55:0x0021 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00e4 A[Catch: Exception -> 0x00fd, TryCatch #0 {Exception -> 0x00fd, blocks: (B:13:0x0033, B:35:0x00a2, B:37:0x00aa, B:39:0x00c3, B:41:0x00c8, B:45:0x00ce, B:40:0x00c6, B:46:0x00d6, B:49:0x00e4, B:51:0x00f7, B:18:0x0046, B:29:0x0074, B:31:0x0081, B:21:0x0050, B:25:0x0061), top: B:55:0x0021 }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00f7 A[Catch: Exception -> 0x00fd, TRY_LEAVE, TryCatch #0 {Exception -> 0x00fd, blocks: (B:13:0x0033, B:35:0x00a2, B:37:0x00aa, B:39:0x00c3, B:41:0x00c8, B:45:0x00ce, B:40:0x00c6, B:46:0x00d6, B:49:0x00e4, B:51:0x00f7, B:18:0x0046, B:29:0x0074, B:31:0x0081, B:21:0x0050, B:25:0x0061), top: B:55:0x0021 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object u(com.quizlet.features.folders.viewmodel.usecases.c r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 256
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.u(com.quizlet.features.folders.viewmodel.usecases.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void v(String str, String str2) {
        ((HashMap) this.a).put(str, str2);
    }

    @Override // com.google.android.gms.internal.ads.Pg
    /* renamed from: w, reason: merged with bridge method [inline-methods] */
    public C1777Te g() {
        AbstractC1981ds.w(Zh.class, (Zh) this.d);
        AbstractC1981ds.w(Sg.class, (Sg) this.e);
        return new C1777Te((C1765Re) this.a, new C2147hi(13, (byte) 0), (Zh) this.d, (Sg) this.e, new Ts(), (Gp) this.b, (C2754vp) this.c);
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0062 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0063  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public byte[] x() throws java.lang.Throwable {
        /*
            r9 = this;
            java.lang.Object r0 = r9.e
            byte[] r0 = (byte[]) r0
            r1 = 0
            if (r0 != 0) goto L5c
            java.lang.Object r0 = r9.d
            java.io.File r0 = (java.io.File) r0
            java.io.FileInputStream r2 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> L50 java.io.IOException -> L55
            r2.<init>(r0)     // Catch: java.lang.Throwable -> L50 java.io.IOException -> L55
            com.google.android.gms.internal.ads.zA r0 = com.google.android.gms.internal.ads.BA.b     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            java.util.ArrayList r0 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            r0.<init>()     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            r3 = 256(0x100, float:3.59E-43)
        L19:
            byte[] r4 = new byte[r3]     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            r5 = 0
            r6 = r5
        L1d:
            if (r6 >= r3) goto L2d
            int r7 = r3 - r6
            int r7 = r2.read(r4, r6, r7)     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            r8 = -1
            if (r7 != r8) goto L29
            goto L2d
        L29:
            int r6 = r6 + r7
            goto L1d
        L2b:
            r0 = move-exception
            goto L4e
        L2d:
            if (r6 != 0) goto L31
            r4 = r1
            goto L35
        L31:
            com.google.android.gms.internal.ads.zA r4 = com.google.android.gms.internal.ads.BA.w(r5, r4, r6)     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
        L35:
            if (r4 != 0) goto L43
            com.google.android.gms.internal.ads.BA r0 = com.google.android.gms.internal.ads.BA.v(r0)     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            byte[] r0 = r0.a()     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            com.google.android.gms.common.util.c.d(r2)
            goto L5a
        L43:
            r0.add(r4)     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            int r3 = r3 + r3
            r4 = 8192(0x2000, float:1.148E-41)
            int r3 = java.lang.Math.min(r3, r4)     // Catch: java.lang.Throwable -> L2b java.io.IOException -> L56
            goto L19
        L4e:
            r1 = r2
            goto L51
        L50:
            r0 = move-exception
        L51:
            com.google.android.gms.common.util.c.d(r1)
            throw r0
        L55:
            r2 = r1
        L56:
            com.google.android.gms.common.util.c.d(r2)
            r0 = r1
        L5a:
            r9.e = r0
        L5c:
            java.lang.Object r0 = r9.e
            byte[] r0 = (byte[]) r0
            if (r0 != 0) goto L63
            return r1
        L63:
            int r1 = r0.length
            byte[] r0 = java.util.Arrays.copyOf(r0, r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.client.C1608n.x():byte[]");
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Tq tq;
        C2601s7 c2601s7 = AbstractC2773w7.L5;
        r rVar = r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            com.google.android.gms.ads.internal.util.A.m();
        }
        C2454op c2454op = (C2454op) this.e;
        C1777Te c1777Te = (C1777Te) c2454op.e.j();
        zze zzeVarL = c1777Te == null ? AbstractC1972di.l(th, null) : AbstractC1972di.l(th, c1777Te.zzb().l);
        synchronized (c2454op) {
            try {
                c2454op.j = null;
                if (c1777Te != null) {
                    ((Zg) c1777Te.a0.zzb()).m0(zzeVarL);
                    if (((Boolean) rVar.c.a(AbstractC2773w7.h8)).booleanValue()) {
                        c2454op.b.execute(new RunnableC2793wl(7, this, zzeVarL));
                    }
                } else {
                    c2454op.d.m0(zzeVarL);
                    c2454op.b((C2368mp) this.d).g().zzb().f.g();
                }
                AbstractC1795We.n(zzeVarL.a, "AppOpenAdLoader.onFailure", th);
                ((Rn) this.a).zza();
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = c2454op.h;
                    Pq pq = (Pq) this.c;
                    pq.j(zzeVarL);
                    pq.g(th);
                    pq.h(false);
                    uq.b(pq.l());
                } else {
                    tq.c(zzeVarL);
                    Pq pq2 = (Pq) this.c;
                    pq2.g(th);
                    pq2.h(false);
                    tq.a(pq2);
                    tq.h();
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    public C1608n() {
        this.a = new HashMap();
        this.c = new HashMap();
        this.d = new ArrayList();
        this.e = new ArrayList();
        v("&t", "screenview");
    }

    public C1608n(UserInfoCache userInfoCache, androidx.work.impl.model.c userProps, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, com.quizlet.data.repository.user.a subfolderFeature, com.quizlet.data.repository.explanations.myexplanations.a validateFolderTagUseCase) {
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(subfolderFeature, "subfolderFeature");
        Intrinsics.checkNotNullParameter(validateFolderTagUseCase, "validateFolderTagUseCase");
        this.a = userInfoCache;
        this.b = userProps;
        this.c = checkNotesEligibilityUseCase;
        this.d = subfolderFeature;
        this.e = validateFolderTagUseCase;
    }
}

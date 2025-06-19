package com.android.volley;

import assistantMode.refactored.modelTypes.CustomMultipleChoiceQuestion;
import assistantMode.types.C1460g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;

/* loaded from: classes.dex */
public final class m implements o {
    public Object a;

    public /* synthetic */ m(Object obj) {
        this.a = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x003a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public assistantMode.types.B a(assistantMode.enums.k r6, assistantMode.types.C1454a r7, androidx.compose.runtime.internal.j r8, assistantMode.utils.h r9, assistantMode.types.test.TestSettings r10, java.util.LinkedHashSet r11, boolean r12) {
        /*
            r5 = this;
            java.lang.String r0 = "questionType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = "card"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r0 = "testSettings"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            java.lang.String r0 = "studiableMaterialDataSource"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.util.List r0 = r10.b
            int r1 = r0.size()
            r2 = 0
            r3 = 1
            if (r1 != r3) goto L3a
            java.lang.Object r0 = r0.get(r2)
            assistantMode.types.A r1 = assistantMode.questions.a.b
            assistantMode.enums.m r4 = r1.a
            if (r0 != r4) goto L3a
            java.util.List r0 = r10.c
            int r4 = r0.size()
            if (r4 != r3) goto L3a
            java.lang.Object r0 = r0.get(r2)
            assistantMode.enums.m r1 = r1.b
            if (r0 != r1) goto L3a
            r0 = r3
            goto L3b
        L3a:
            r0 = r2
        L3b:
            assistantMode.enums.k r1 = assistantMode.enums.k.b
            if (r6 != r1) goto L7a
            if (r0 == 0) goto L7a
            assistantMode.enums.m r0 = assistantMode.enums.m.c
            com.google.android.gms.internal.mlkit_vision_camera.k3 r1 = r7.i(r0)
            java.lang.String r1 = r1.e()
            int r1 = r1.length()
            if (r1 != 0) goto L7a
            assistantMode.types.unions.ImageAttribute r0 = r7.h(r0)
            if (r0 == 0) goto L7a
            assistantMode.types.d r0 = new assistantMode.types.d
            assistantMode.types.A r1 = assistantMode.questions.a.b
            assistantMode.enums.m r4 = r1.a
            assistantMode.enums.m r1 = r1.b
            r0.<init>(r7, r4, r1)
            boolean r0 = androidx.compose.runtime.internal.j.t(r0, r9, r6)
            if (r0 != 0) goto L7a
            assistantMode.types.d r0 = new assistantMode.types.d
            assistantMode.types.A r1 = assistantMode.questions.a.a
            assistantMode.enums.m r4 = r1.a
            assistantMode.enums.m r1 = r1.b
            r0.<init>(r7, r4, r1)
            boolean r9 = androidx.compose.runtime.internal.j.t(r0, r9, r6)
            if (r9 == 0) goto L7a
            r2 = r3
        L7a:
            if (r2 == 0) goto L83
            assistantMode.types.A r9 = assistantMode.questions.a.a
            java.util.List r9 = kotlin.collections.A.b(r9)
            goto L87
        L83:
            java.util.ArrayList r9 = r5.c(r6, r10)
        L87:
            kotlin.collections.w r9 = kotlin.collections.CollectionsKt.D(r9)
            androidx.compose.ui.viewinterop.b r10 = new androidx.compose.ui.viewinterop.b
            r0 = 29
            r10.<init>(r0, r11, r7)
            kotlin.sequences.f r9 = kotlin.sequences.q.e(r9, r10)
            androidx.credentials.playservices.controllers.BeginSignIn.c r10 = new androidx.credentials.playservices.controllers.BeginSignIn.c
            r11 = 22
            r10.<init>(r7, r11)
            kotlin.sequences.t r7 = kotlin.sequences.q.h(r9, r10)
            androidx.compose.foundation.text.J r9 = new androidx.compose.foundation.text.J
            r9.<init>(r2, r8, r6, r12)
            kotlin.sequences.f r7 = kotlin.sequences.q.e(r7, r9)
            androidx.camera.core.impl.utils.a r9 = new androidx.camera.core.impl.utils.a
            r9.<init>(r8, r6)
            java.lang.String r6 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r6)
            java.lang.String r8 = "comparator"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r8)
            kotlin.sequences.g r8 = new kotlin.sequences.g
            r8.<init>(r7, r9)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r6)
            java.util.Iterator r6 = r8.iterator()
            boolean r7 = r6.hasNext()
            if (r7 != 0) goto Lcd
            r6 = 0
            goto Ld1
        Lcd:
            java.lang.Object r6 = r6.next()
        Ld1:
            assistantMode.types.B r6 = (assistantMode.types.B) r6
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.volley.m.a(assistantMode.enums.k, assistantMode.types.a, androidx.compose.runtime.internal.j, assistantMode.utils.h, assistantMode.types.test.TestSettings, java.util.LinkedHashSet, boolean):assistantMode.types.B");
    }

    @Override // com.android.volley.o
    public boolean apply(l lVar) {
        return lVar.getTag() == this.a;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    public List b(assistantMode.utils.h hVar, int i) {
        ArrayList arrayList = hVar.b;
        if (arrayList.isEmpty()) {
            return K.a;
        }
        List listP0 = CollectionsKt.p0(B.n(arrayList, (kotlin.random.e) this.a.getValue()), i);
        ArrayList arrayList2 = new ArrayList(C.q(listP0, 10));
        Iterator it2 = listP0.iterator();
        while (it2.hasNext()) {
            arrayList2.add(new C1460g((CustomMultipleChoiceQuestion) it2.next()));
        }
        return arrayList2;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0097  */
    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.ArrayList c(assistantMode.enums.k r8, assistantMode.types.test.TestSettings r9) {
        /*
            r7 = this;
            java.lang.Object r0 = r7.a
            java.lang.Object r1 = r0.getValue()
            kotlin.random.e r1 = (kotlin.random.e) r1
            java.util.List r2 = r9.b
            java.util.List r1 = kotlin.collections.B.n(r2, r1)
            java.lang.Object r0 = r0.getValue()
            kotlin.random.e r0 = (kotlin.random.e) r0
            java.util.List r9 = r9.c
            java.util.List r9 = kotlin.collections.B.n(r9, r0)
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            java.util.ArrayList r1 = (java.util.ArrayList) r1
            java.util.Iterator r1 = r1.iterator()
        L25:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto L5c
            java.lang.Object r2 = r1.next()
            assistantMode.enums.m r2 = (assistantMode.enums.m) r2
            java.util.ArrayList r3 = new java.util.ArrayList
            r4 = 10
            int r4 = kotlin.collections.C.q(r9, r4)
            r3.<init>(r4)
            r4 = r9
            java.util.ArrayList r4 = (java.util.ArrayList) r4
            java.util.Iterator r4 = r4.iterator()
        L43:
            boolean r5 = r4.hasNext()
            if (r5 == 0) goto L58
            java.lang.Object r5 = r4.next()
            assistantMode.enums.m r5 = (assistantMode.enums.m) r5
            assistantMode.types.A r6 = new assistantMode.types.A
            r6.<init>(r2, r5)
            r3.add(r6)
            goto L43
        L58:
            kotlin.collections.G.u(r0, r3)
            goto L25
        L5c:
            java.util.ArrayList r9 = new java.util.ArrayList
            r9.<init>()
            java.util.Iterator r0 = r0.iterator()
        L65:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L9e
            java.lang.Object r1 = r0.next()
            r2 = r1
            assistantMode.types.A r2 = (assistantMode.types.A) r2
            assistantMode.enums.m r3 = r2.a
            assistantMode.enums.m r4 = r2.b
            if (r3 == r4) goto L97
            java.lang.String r3 = "sidePair"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            java.lang.String r3 = "questionType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r3)
            assistantMode.enums.m r3 = assistantMode.enums.m.d
            assistantMode.enums.m r2 = r2.a
            r5 = 1
            if (r2 == r3) goto L8e
            if (r4 != r3) goto L8c
            goto L8e
        L8c:
            r2 = r5
            goto L94
        L8e:
            java.util.List r2 = test.utils.l.a
            boolean r2 = r2.contains(r8)
        L94:
            if (r2 == 0) goto L97
            goto L98
        L97:
            r5 = 0
        L98:
            if (r5 == 0) goto L65
            r9.add(r1)
            goto L65
        L9e:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.volley.m.c(assistantMode.enums.k, assistantMode.types.test.TestSettings):java.util.ArrayList");
    }

    /* JADX WARN: Removed duplicated region for block: B:98:0x02e3  */
    /* JADX WARN: Type inference failed for: r15v0, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r1v5, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.LinkedHashMap d(assistantMode.types.test.TestSettings r24, assistantMode.utils.h r25, androidx.compose.runtime.internal.j r26) {
        /*
            Method dump skipped, instructions count: 956
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.volley.m.d(assistantMode.types.test.TestSettings, assistantMode.utils.h, androidx.compose.runtime.internal.j):java.util.LinkedHashMap");
    }

    public m() {
        this.a = kotlin.l.a(kotlin.m.a, new assistantMode.grading.o(0, 6));
    }
}

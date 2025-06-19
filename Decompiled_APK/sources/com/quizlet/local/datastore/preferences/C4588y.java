package com.quizlet.local.datastore.preferences;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.local.datastore.preferences.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4588y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ C4589z k;
    public final /* synthetic */ ArrayList l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4588y(C4589z c4589z, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4589z;
        this.l = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4588y c4588y = new C4588y(this.k, this.l, hVar);
        c4588y.j = obj;
        return c4588y;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4588y) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0086 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0015 A[SYNTHETIC] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r11.j
            androidx.datastore.preferences.core.b r12 = (androidx.datastore.preferences.core.b) r12
            java.util.Map r0 = r12.a()
            java.util.Set r0 = r0.entrySet()
            java.util.Iterator r0 = r0.iterator()
        L15:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L90
            java.lang.Object r1 = r0.next()
            java.util.Map$Entry r1 = (java.util.Map.Entry) r1
            java.lang.Object r2 = r1.getKey()
            androidx.datastore.preferences.core.f r2 = (androidx.datastore.preferences.core.f) r2
            java.lang.String r2 = r2.a
            r3 = 0
            kotlin.io.encoding.a r4 = kotlin.io.encoding.c.c     // Catch: java.lang.Exception -> L79
            r5 = 6
            r6 = 0
            byte[] r2 = kotlin.io.encoding.c.a(r4, r2, r6, r5)     // Catch: java.lang.Exception -> L79
            java.lang.String r2 = kotlin.text.D.i(r2)     // Catch: java.lang.Exception -> L79
            java.lang.String r4 = ":"
            java.lang.String[] r4 = new java.lang.String[]{r4}     // Catch: java.lang.Exception -> L79
            java.util.List r2 = kotlin.text.StringsKt.W(r2, r4, r6, r5)     // Catch: java.lang.Exception -> L79
            int r4 = r2.size()     // Catch: java.lang.Exception -> L79
            r5 = 2
            if (r4 >= r5) goto L48
            goto L79
        L48:
            com.quizlet.data.model.V r4 = new com.quizlet.data.model.V     // Catch: java.lang.Exception -> L79
            java.lang.Object r6 = r2.get(r6)     // Catch: java.lang.Exception -> L79
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Exception -> L79
            r7 = 1
            java.lang.Object r7 = r2.get(r7)     // Catch: java.lang.Exception -> L79
            java.lang.String r7 = (java.lang.String) r7     // Catch: java.lang.Exception -> L79
            int r8 = r2.size()     // Catch: java.lang.Exception -> L79
            java.lang.String r9 = ""
            if (r8 <= r5) goto L66
            java.lang.Object r5 = r2.get(r5)     // Catch: java.lang.Exception -> L79
            java.lang.String r5 = (java.lang.String) r5     // Catch: java.lang.Exception -> L79
            goto L67
        L66:
            r5 = r9
        L67:
            int r8 = r2.size()     // Catch: java.lang.Exception -> L79
            r10 = 3
            if (r8 <= r10) goto L75
            java.lang.Object r2 = r2.get(r10)     // Catch: java.lang.Exception -> L79
            r9 = r2
            java.lang.String r9 = (java.lang.String) r9     // Catch: java.lang.Exception -> L79
        L75:
            r4.<init>(r6, r7, r5, r9)     // Catch: java.lang.Exception -> L79
            goto L7a
        L79:
            r4 = r3
        L7a:
            if (r4 == 0) goto L7e
            java.lang.String r3 = r4.a
        L7e:
            java.util.ArrayList r2 = r11.l
            boolean r2 = kotlin.collections.CollectionsKt.F(r2, r3)
            if (r2 != 0) goto L15
            java.lang.Object r1 = r1.getKey()
            androidx.datastore.preferences.core.f r1 = (androidx.datastore.preferences.core.f) r1
            r12.d(r1)
            goto L15
        L90:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.datastore.preferences.C4588y.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}

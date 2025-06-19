package com.quizlet.features.questiontypes.written.ui;

import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function2 b;

    public /* synthetic */ f(Function2 function2, int i) {
        this.a = i;
        this.b = function2;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003a  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r6, java.lang.Object r7) {
        /*
            r5 = this;
            kotlin.jvm.functions.Function2 r0 = r5.b
            int r1 = r5.a
            switch(r1) {
                case 0: goto L57;
                default: goto L7;
            }
        L7:
            io.ktor.client.plugins.N r6 = (io.ktor.client.plugins.N) r6
            java.lang.Integer r7 = (java.lang.Integer) r7
            r7.getClass()
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            io.ktor.client.statement.b r1 = r6.b
            if (r1 == 0) goto L3a
            io.ktor.http.k r1 = r1.a()
            if (r1 == 0) goto L3a
            java.util.List r2 = io.ktor.http.n.a
            java.lang.String r2 = "Retry-After"
            java.lang.String r1 = r1.d(r2)
            if (r1 == 0) goto L3a
            java.lang.Long r1 = kotlin.text.StringsKt.f0(r1)
            if (r1 == 0) goto L3a
            long r1 = r1.longValue()
            r3 = 1000(0x3e8, float:1.401E-42)
            long r3 = (long) r3
            long r1 = r1 * r3
            java.lang.Long r1 = java.lang.Long.valueOf(r1)
            goto L3b
        L3a:
            r1 = 0
        L3b:
            java.lang.Object r6 = r0.invoke(r6, r7)
            java.lang.Number r6 = (java.lang.Number) r6
            long r6 = r6.longValue()
            if (r1 == 0) goto L4c
            long r0 = r1.longValue()
            goto L4e
        L4c:
            r0 = 0
        L4e:
            long r6 = java.lang.Math.max(r6, r0)
            java.lang.Long r6 = java.lang.Long.valueOf(r6)
            return r6
        L57:
            java.lang.String r6 = (java.lang.String) r6
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            r7.booleanValue()
            java.lang.String r1 = "response"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            r0.invoke(r6, r7)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.written.ui.f.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}

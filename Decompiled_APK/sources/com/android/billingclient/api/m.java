package com.android.billingclient.api;

/* loaded from: classes.dex */
public final class m implements io.reactivex.rxjava3.functions.h {
    public final String a;

    /* JADX WARN: Removed duplicated region for block: B:12:0x0041  */
    @Override // io.reactivex.rxjava3.functions.h
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object apply(java.lang.Object r4) {
        /*
            r3 = this;
            com.quizlet.billing.model.a r4 = (com.quizlet.billing.model.a) r4
            java.lang.String r0 = "inventory"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            r4.getClass()
            java.lang.String r0 = r3.a
            java.lang.String r1 = "sku"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.util.LinkedHashMap r2 = r4.a
            boolean r2 = r2.containsKey(r0)
            if (r2 == 0) goto L41
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.util.LinkedHashMap r4 = r4.c
            boolean r2 = r4.containsKey(r0)
            if (r2 == 0) goto L3f
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.Object r4 = r4.get(r0)
            com.android.billingclient.api.Purchase r4 = (com.android.billingclient.api.Purchase) r4
            if (r4 == 0) goto L3c
            org.json.JSONObject r4 = r4.c
            java.lang.String r0 = "purchaseTime"
            long r0 = r4.optLong(r0)
            java.lang.Long r4 = java.lang.Long.valueOf(r0)
            goto L3d
        L3c:
            r4 = 0
        L3d:
            if (r4 == 0) goto L41
        L3f:
            r4 = 1
            goto L42
        L41:
            r4 = 0
        L42:
            java.lang.Boolean r4 = java.lang.Boolean.valueOf(r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.billingclient.api.m.apply(java.lang.Object):java.lang.Object");
    }

    public m(String str) {
        this.a = str;
    }
}

package com.amazon.aps.ads.privacy;

import android.content.SharedPreferences;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements SharedPreferences.OnSharedPreferenceChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0074  */
    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onSharedPreferenceChanged(android.content.SharedPreferences r6, java.lang.String r7) {
        /*
            r5 = this;
            int r0 = r5.a
            switch(r0) {
                case 0: goto Ld;
                default: goto L5;
            }
        L5:
            java.lang.Object r0 = r5.b
            org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager r0 = (org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager) r0
            r0.b(r6, r7)
            return
        Ld:
            java.lang.Object r0 = r5.b
            com.amazon.aps.ads.privacy.c r0 = (com.amazon.aps.ads.privacy.c) r0
            java.lang.String r1 = "this$0"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.String r1 = "Received the shared preference changed event"
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u.a(r0, r1)
            java.lang.String r1 = "IABTCF_TCString"
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r7, r1)
            java.lang.String r2 = "prefs"
            com.amazon.aps.ads.privacy.a r3 = r0.c
            if (r1 == 0) goto L32
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r2)
            java.lang.String r6 = r0.a(r6)
            r3.a(r6)
            goto L97
        L32:
            java.lang.String r1 = "IABTCF_gdprApplies"
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r7, r1)
            if (r4 == 0) goto L97
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r2)
            java.lang.String r2 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            boolean r2 = r6.contains(r1)
            r4 = 0
            if (r2 == 0) goto L95
            java.util.Map r6 = r6.getAll()
            java.lang.Object r6 = r6.get(r1)
            boolean r1 = r6 instanceof java.lang.Boolean
            if (r1 == 0) goto L63
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            boolean r6 = r1.equals(r6)
            java.lang.Boolean r4 = java.lang.Boolean.valueOf(r6)
            goto L95
        L63:
            boolean r1 = r6 instanceof java.lang.Integer
            if (r1 == 0) goto L7a
            if (r6 != 0) goto L6a
            goto L74
        L6a:
            java.lang.Number r6 = (java.lang.Number) r6
            int r6 = r6.intValue()
            r1 = 1
            if (r1 != r6) goto L74
            goto L75
        L74:
            r1 = 0
        L75:
            java.lang.Boolean r4 = java.lang.Boolean.valueOf(r1)
            goto L95
        L7a:
            boolean r1 = r6 instanceof java.lang.String
            if (r1 == 0) goto L95
            java.lang.String r6 = (java.lang.String) r6
            java.util.Locale r1 = java.util.Locale.ROOT
            java.lang.String r6 = r6.toLowerCase(r1)
            java.lang.String r1 = "this as java.lang.String).toLowerCase(Locale.ROOT)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r1)
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            boolean r6 = r6.equals(r1)
            java.lang.Boolean r4 = java.lang.Boolean.valueOf(r6)
        L95:
            r3.d = r4
        L97:
            java.util.Set r6 = r0.a
            boolean r6 = r6.contains(r7)
            if (r6 == 0) goto La2
            r0.d()
        La2:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.aps.ads.privacy.b.onSharedPreferenceChanged(android.content.SharedPreferences, java.lang.String):void");
    }
}

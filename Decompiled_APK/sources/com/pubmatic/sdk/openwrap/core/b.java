package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.models.a;

/* loaded from: classes2.dex */
public class b {
    public static p getImpression(v vVar) {
        p[] impressions;
        if (vVar == null || (impressions = vVar.getImpressions()) == null || impressions.length == 0) {
            return null;
        }
        return impressions[0];
    }

    @NonNull
    public static <T extends com.pubmatic.sdk.common.base.c> com.pubmatic.sdk.common.models.a updateResponseUsingPlacementType(@NonNull com.pubmatic.sdk.common.models.a aVar, @NonNull String str) {
        return aVar.getWinningBid() != null ? new a.C0010a(aVar).updateWithRefreshIntervalAndExpiryTimeout(str).build() : aVar;
    }

    public static boolean validate(Context context, String str, String str2, Object obj) {
        return (context == null || obj == null || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str) || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str2)) ? false : true;
    }
}

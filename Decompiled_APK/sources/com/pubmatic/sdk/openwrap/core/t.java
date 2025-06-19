package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import androidx.annotation.NonNull;
import java.util.Set;

/* loaded from: classes2.dex */
public class t {

    public static class a implements com.pubmatic.sdk.common.base.e {

        @NonNull
        private final com.pubmatic.sdk.common.models.i a;

        public a(@NonNull com.pubmatic.sdk.common.models.i iVar) {
            this.a = iVar;
        }

        @Override // com.pubmatic.sdk.common.base.e
        public String getCountryFilteringMode() {
            return this.a.getCountryFilteringMode();
        }

        @Override // com.pubmatic.sdk.common.base.e
        public Set<String> getFilteringCountries() {
            return this.a.getFilteringCountries();
        }
    }

    @NonNull
    public static r createPOBManager(@NonNull Context context, @NonNull v vVar, com.pubmatic.sdk.common.models.i iVar) {
        r rVar = new r(vVar, context);
        rVar.setIdentifier("OpenWrap");
        if (iVar != null) {
            rVar.setCountryFilterConfig(new a(iVar));
        }
        return rVar;
    }
}

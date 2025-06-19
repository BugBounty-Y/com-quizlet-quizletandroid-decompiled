package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class zzny implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        String language;
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        Locale locale = Locale.getDefault();
        if (locale != null && (language = locale.getLanguage()) != null) {
            return new zzqz(language.toLowerCase());
        }
        return new zzqz("");
    }
}

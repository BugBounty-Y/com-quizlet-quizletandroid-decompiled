package com.google.android.gms.internal.ads;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Mi implements CC {
    public final /* synthetic */ int a;
    public final com.quizlet.data.repository.achievements.h b;

    public /* synthetic */ Mi(com.quizlet.data.repository.achievements.h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                JSONObject jSONObject = (JSONObject) this.b.a;
                AbstractC1981ds.s(jSONObject);
                return jSONObject;
            case 1:
                C1843ak c1843ak = (C1843ak) this.b.b;
                AbstractC1981ds.s(c1843ak);
                return c1843ak;
            case 2:
                return (com.google.android.gms.ads.internal.a) this.b.c;
            default:
                return (C1673Cc) this.b.d;
        }
    }
}

package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.gp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2110gp implements Vo {
    public final JSONObject a;

    public C2110gp(Context context) {
        this.a = com.quizlet.data.repository.studysetwithcreatorinclass.g.z(context, VersionInfoParcel.a());
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 46;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Vb)).booleanValue() ? AbstractC2025es.E(new C2066fp()) : AbstractC2025es.E(new Ho(this, 2));
    }
}

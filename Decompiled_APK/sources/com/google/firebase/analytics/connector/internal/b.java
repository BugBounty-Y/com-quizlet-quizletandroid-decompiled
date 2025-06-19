package com.google.firebase.analytics.connector.internal;

import android.os.Bundle;
import androidx.work.impl.model.c;
import androidx.work.impl.model.l;
import com.google.android.gms.measurement.internal.AbstractC3883n0;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;
import com.google.common.collect.o;
import java.util.HashSet;

/* loaded from: classes2.dex */
public final class b implements InterfaceC3887p0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3887p0
    public final void onEvent(String str, String str2, Bundle bundle, long j) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                c cVar = (c) obj;
                if (((HashSet) cVar.b).contains(str2)) {
                    Bundle bundle2 = new Bundle();
                    o oVar = a.a;
                    String strD = AbstractC3883n0.d(str2, AbstractC3883n0.c, AbstractC3883n0.a);
                    if (strD != null) {
                        str2 = strD;
                    }
                    bundle2.putString("events", str2);
                    ((l) cVar.c).p(bundle2);
                    break;
                }
                break;
            default:
                if (str != null && !a.a.contains(str2)) {
                    Bundle bundle3 = new Bundle();
                    bundle3.putString("name", str2);
                    bundle3.putLong("timestampInMillis", j);
                    bundle3.putBundle("params", bundle);
                    ((l) ((com.google.firebase.platforminfo.c) obj).a).p(bundle3);
                    break;
                }
                break;
        }
    }
}

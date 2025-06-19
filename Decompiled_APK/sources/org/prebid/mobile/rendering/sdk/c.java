package org.prebid.mobile.rendering.sdk;

import com.google.android.datatransport.runtime.i;
import com.google.android.datatransport.runtime.scheduling.jobscheduling.k;
import com.google.android.datatransport.runtime.scheduling.persistence.g;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements com.google.android.datatransport.runtime.synchronization.a {
    public final /* synthetic */ Object a;

    public /* synthetic */ c(Object obj) {
        this.a = obj;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        k kVar = (k) this.a;
        Iterator it2 = ((Iterable) ((g) kVar.b).f(new com.facebook.appevents.k(17))).iterator();
        while (it2.hasNext()) {
            kVar.c.a((i) it2.next(), 1, false);
        }
        return null;
    }
}

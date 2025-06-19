package com.google.firebase.crashlytics.internal;

import android.util.Log;
import androidx.webkit.internal.p;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.crashlytics.internal.metadata.o;
import com.google.firebase.remoteconfig.interop.rollouts.e;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d a;

    public b(com.onetrust.otpublishers.headless.UI.TVUI.datautils.d userMetadata) {
        Intrinsics.checkNotNullParameter(userMetadata, "userMetadata");
        this.a = userMetadata;
    }

    public final void a(com.google.firebase.remoteconfig.interop.rollouts.d rolloutsState) {
        int i = 3;
        Intrinsics.checkNotNullParameter(rolloutsState, "rolloutsState");
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = this.a;
        HashSet hashSet = rolloutsState.a;
        Intrinsics.checkNotNullExpressionValue(hashSet, "rolloutsState.rolloutAssignments");
        ArrayList arrayList = new ArrayList(C.q(hashSet, 10));
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            com.google.firebase.remoteconfig.interop.rollouts.c cVar = (com.google.firebase.remoteconfig.interop.rollouts.c) ((e) it2.next());
            String str = cVar.b;
            String str2 = cVar.d;
            String strSubstring = cVar.e;
            String str3 = cVar.c;
            long j = cVar.f;
            p pVar = o.a;
            if (strSubstring.length() > 256) {
                strSubstring = strSubstring.substring(0, 256);
            }
            arrayList.add(new com.google.firebase.crashlytics.internal.metadata.b(str, str2, strSubstring, str3, j));
        }
        synchronized (((com.google.firebase.crashlytics.internal.metadata.p) dVar.f)) {
            try {
                if (((com.google.firebase.crashlytics.internal.metadata.p) dVar.f).d(arrayList)) {
                    ((com.google.firebase.crashlytics.internal.concurrency.d) dVar.c).b.a(new i(i, dVar, ((com.google.firebase.crashlytics.internal.metadata.p) dVar.f).b()));
                }
            } finally {
            }
        }
        Log.isLoggable("FirebaseCrashlytics", 3);
    }
}

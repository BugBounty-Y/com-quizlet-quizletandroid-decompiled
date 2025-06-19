package com.google.android.datatransport.runtime;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;

/* loaded from: classes2.dex */
public final class m implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final /* synthetic */ int a;

    public /* synthetic */ m(int i) {
        this.a = i;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new androidx.camera.core.impl.utils.executor.g(Executors.newSingleThreadExecutor());
            default:
                com.quizlet.shared.usecase.folderstudymaterials.c cVar = new com.quizlet.shared.usecase.folderstudymaterials.c(8);
                HashMap map = new HashMap();
                com.google.android.datatransport.d dVar = com.google.android.datatransport.d.a;
                Set set = Collections.EMPTY_SET;
                if (set == null) {
                    throw new NullPointerException("Null flags");
                }
                map.put(dVar, new com.google.android.datatransport.runtime.scheduling.jobscheduling.b(30000L, 86400000L, set));
                com.google.android.datatransport.d dVar2 = com.google.android.datatransport.d.c;
                if (set == null) {
                    throw new NullPointerException("Null flags");
                }
                map.put(dVar2, new com.google.android.datatransport.runtime.scheduling.jobscheduling.b(1000L, 86400000L, set));
                com.google.android.datatransport.d dVar3 = com.google.android.datatransport.d.b;
                if (set == null) {
                    throw new NullPointerException("Null flags");
                }
                Set setUnmodifiableSet = Collections.unmodifiableSet(new HashSet(Arrays.asList(com.google.android.datatransport.runtime.scheduling.jobscheduling.d.b)));
                if (setUnmodifiableSet == null) {
                    throw new NullPointerException("Null flags");
                }
                map.put(dVar3, new com.google.android.datatransport.runtime.scheduling.jobscheduling.b(86400000L, 86400000L, setUnmodifiableSet));
                if (map.keySet().size() < com.google.android.datatransport.d.values().length) {
                    throw new IllegalStateException("Not all priorities have been configured");
                }
                new HashMap();
                return new com.google.android.datatransport.runtime.scheduling.jobscheduling.a(cVar, map);
        }
    }
}

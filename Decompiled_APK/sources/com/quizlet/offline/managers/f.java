package com.quizlet.offline.managers;

/* loaded from: classes3.dex */
public final class f implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ f(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x003a, code lost:
    
        r1.put(r2, r6);
     */
    @Override // io.reactivex.rxjava3.functions.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void accept(java.lang.Object r9) {
        /*
            r8 = this;
            int r0 = r8.a
            switch(r0) {
                case 0: goto L9b;
                case 1: goto L82;
                case 2: goto L4a;
                default: goto L5;
            }
        L5:
            java.util.List r9 = (java.util.List) r9
            java.lang.String r0 = "offlineEntities"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.util.Iterator r9 = r9.iterator()
        L10:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto L49
            java.lang.Object r0 = r9.next()
            com.quizlet.db.data.models.persisted.DBOfflineEntity r0 = (com.quizlet.db.data.models.persisted.DBOfflineEntity) r0
            com.quizlet.offline.managers.i r1 = r8.b
            java.util.LinkedHashMap r1 = r1.j
            long r2 = r0.getSavedModelId()
            java.lang.Long r2 = java.lang.Long.valueOf(r2)
            int r0 = r0.getOfflineStatus()
            com.quizlet.features.infra.models.b[] r3 = com.quizlet.features.infra.models.b.values()
            int r4 = r3.length
            r5 = 0
        L32:
            if (r5 >= r4) goto L41
            r6 = r3[r5]
            int r7 = r6.a
            if (r7 != r0) goto L3e
            r1.put(r2, r6)
            goto L10
        L3e:
            int r5 = r5 + 1
            goto L32
        L41:
            java.util.NoSuchElementException r9 = new java.util.NoSuchElementException
            java.lang.String r0 = "Array contains no element matching the predicate."
            r9.<init>(r0)
            throw r9
        L49:
            return
        L4a:
            java.util.List r9 = (java.util.List) r9
            java.lang.String r0 = "sets"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            timber.log.a r0 = timber.log.c.a
            int r1 = r9.size()
            java.lang.String r2 = "Pre-loading from Latest Activity Feed complete. "
            java.lang.String r3 = " sets fully loaded"
            java.lang.String r1 = androidx.camera.camera2.internal.AbstractC0147y.c(r1, r2, r3)
            r2 = 0
            java.lang.Object[] r2 = new java.lang.Object[r2]
            r0.g(r1, r2)
            java.util.Iterator r9 = r9.iterator()
        L69:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto L81
            java.lang.Object r0 = r9.next()
            com.quizlet.db.data.models.persisted.DBStudySet r0 = (com.quizlet.db.data.models.persisted.DBStudySet) r0
            com.quizlet.offline.managers.i r1 = r8.b
            android.util.LongSparseArray r1 = r1.h
            long r2 = r0.getId()
            r1.remove(r2)
            goto L69
        L81:
            return
        L82:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            java.lang.String r0 = "it"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            timber.log.a r9 = timber.log.c.a
            r0 = 0
            java.lang.Object[] r0 = new java.lang.Object[r0]
            java.lang.String r1 = "Clearing the offline state cache"
            r9.g(r1, r0)
            com.quizlet.offline.managers.i r9 = r8.b
            android.util.LongSparseArray r9 = r9.h
            r9.clear()
            return
        L9b:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            java.lang.String r0 = "isConnected"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            boolean r9 = r9.booleanValue()
            com.quizlet.offline.managers.i r0 = r8.b
            r0.i = r9
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.offline.managers.f.accept(java.lang.Object):void");
    }
}

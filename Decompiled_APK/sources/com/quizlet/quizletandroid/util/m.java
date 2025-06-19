package com.quizlet.quizletandroid.util;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.EventLog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ n a;

    public m(n nVar) {
        this.a = nVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        l storageData = (l) obj;
        Intrinsics.checkNotNullParameter(storageData, "storageData");
        n nVar = this.a;
        nVar.e.i(EventLog.DiskSpace.b, storageData.b);
        EventLog.DiskSpace diskSpace = EventLog.DiskSpace.a;
        int i = storageData.a;
        EventLogger eventLogger = nVar.e;
        eventLogger.i(diskSpace, i);
        eventLogger.i(EventLog.DiskSpace.c, storageData.c);
        eventLogger.i(EventLog.DiskSpace.d, storageData.d);
    }
}

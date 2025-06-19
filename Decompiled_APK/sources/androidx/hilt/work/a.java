package androidx.hilt.work;

import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import androidx.work.T;
import androidx.work.WorkerParameters;
import androidx.work.y;
import com.google.common.collect.C;
import com.quizlet.background.eventlogging.EventLogSyncingWorker;
import com.quizlet.background.metering.MeteringSyncWorker;
import com.quizlet.background.progress.ProgressResetSyncWorker;
import com.quizlet.background.widget.WidgetUpdateWorker;
import com.quizlet.data.interactor.metering.e;
import com.quizlet.data.repository.folderset.c;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.local.datastore.models.metering.i;
import com.quizlet.local.datastore.models.metering.j;
import com.quizlet.quizletandroid.managers.h;
import com.quizlet.quizletandroid.p;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.u;

/* loaded from: classes.dex */
public final class a extends T {
    public final C a;

    public a(C c) {
        this.a = c;
    }

    @Override // androidx.work.T
    public final y a(Context context, String str, WorkerParameters workerParameters) {
        javax.inject.a aVar = (javax.inject.a) this.a.get(str);
        if (aVar == null) {
            return null;
        }
        p pVar = (p) aVar.get();
        switch (pVar.a) {
            case 0:
                t tVar = pVar.b;
                return new EventLogSyncingWorker(context, workerParameters, (EventLogBuilder) tVar.a.k0.get(), (EventLogUploader) tVar.a.I0.get());
            case 1:
                u uVar = pVar.b.a;
                return new MeteringSyncWorker(context, workerParameters, new e(new com.quizlet.data.repository.folderwithcreator.e(uVar.i0(), new com.quizlet.quizletandroid.ui.profile.p(2), com.quizlet.featuregate.injection.a.d()), new c(new i((InterfaceC1076h) uVar.K0.get(), 0), new j(), com.quizlet.featuregate.injection.a.d())));
            case 2:
                u uVar2 = pVar.b.a;
                return new ProgressResetSyncWorker(context, workerParameters, new com.quizlet.data.interactor.progress.e(uVar2.O0(), uVar2.N0()));
            default:
                t tVar2 = pVar.b;
                com.quizlet.data.interactor.widget.a aVarY = tVar2.a.Y();
                u uVar3 = tVar2.a;
                return new WidgetUpdateWorker(context, workerParameters, aVarY, new androidx.camera.camera2.internal.concurrent.a(uVar3.q(), (com.quizlet.local.cache.caches.c) uVar3.N0.get(), (h) uVar3.z0.get(), uVar3.Q()));
        }
    }
}

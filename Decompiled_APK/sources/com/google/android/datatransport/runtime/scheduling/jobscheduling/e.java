package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.camera.camera2.internal.C0132i;
import com.google.android.datatransport.runtime.synchronization.SynchronizationException;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.m;
import java.util.Objects;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ e(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = i;
        this.e = obj3;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
        switch (this.a) {
            case 0:
                com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) this.d;
                int i = this.b;
                Runnable runnable = (Runnable) this.e;
                i iVar2 = (i) this.c;
                com.google.android.datatransport.runtime.synchronization.b bVar = iVar2.f;
                try {
                    try {
                        com.google.android.datatransport.runtime.scheduling.persistence.d dVar = iVar2.c;
                        Objects.requireNonNull(dVar);
                        ((com.google.android.datatransport.runtime.scheduling.persistence.g) bVar).l(new C0132i(dVar, 27));
                        NetworkInfo activeNetworkInfo = ((ConnectivityManager) iVar2.a.getSystemService("connectivity")).getActiveNetworkInfo();
                        if (activeNetworkInfo == null || !activeNetworkInfo.isConnected()) {
                            ((com.google.android.datatransport.runtime.scheduling.persistence.g) bVar).l(new f(i, iVar2, iVar));
                        } else {
                            iVar2.a(iVar, i);
                        }
                    } catch (SynchronizationException unused) {
                        iVar2.d.a(iVar, i + 1, false);
                    }
                    runnable.run();
                    return;
                } catch (Throwable th) {
                    runnable.run();
                    throw th;
                }
            default:
                com.quizlet.quizletandroid.ui.setcreation.viewholders.l lVar = (com.quizlet.quizletandroid.ui.setcreation.viewholders.l) this.c;
                boolean z = lVar.c;
                m mVar = (m) this.d;
                int i2 = this.b;
                if (!z && lVar.a.length() == 0) {
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                    fVar.m();
                    DBTerm dBTermJ = fVar.j(i2);
                    if (dBTermJ != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get()) != null) {
                        ((EditSetFragment) aVar).f0(dBTermJ, com.quizlet.quizletandroid.ui.setcreation.activities.a.a, com.quizlet.quizletandroid.ui.setcreation.activities.a.d);
                    }
                }
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                int i3 = fVar2.j;
                if (i3 != -1) {
                    fVar2.notifyItemChanged(i3, 400);
                }
                O1 o1 = (O1) this.e;
                if (o1 != null) {
                    fVar2.j = i2;
                    fVar2.notifyItemChanged(i2, 400);
                    fVar2.m();
                } else {
                    fVar2.j = -1;
                }
                fVar2.k.b(new CardFocusPosition(i2 - 1, i2, o1));
                if (fVar2.k() != null) {
                    DBTerm dBTermJ2 = fVar2.j(i2);
                    if (dBTermJ2 != null && o1 == null) {
                        com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar2.k();
                        dBTermJ2.getLocalId();
                        dBTermJ2.getId();
                        aVarK.g();
                        return;
                    }
                    if (dBTermJ2 != null && o1 == O1.DEFINITION) {
                        fVar2.k().i("definition", Long.valueOf(dBTermJ2.getLocalId()), Long.valueOf(dBTermJ2.getId()));
                        return;
                    } else {
                        if (dBTermJ2 == null || o1 != O1.WORD) {
                            return;
                        }
                        fVar2.k().i("word", Long.valueOf(dBTermJ2.getLocalId()), Long.valueOf(dBTermJ2.getId()));
                        return;
                    }
                }
                return;
        }
    }
}

package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Zh {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;
    public Object q;

    public Zh() {
        this.a = 1;
        this.h = new androidx.navigation.internal.m();
        this.i = new androidx.navigation.internal.m();
        this.j = new androidx.navigation.internal.m();
        this.k = new androidx.navigation.internal.m();
        this.l = new androidx.navigation.internal.m();
        this.m = new androidx.navigation.internal.m();
        this.n = new com.quizlet.data.repository.user.e();
        this.o = new com.quizlet.data.repository.user.e();
        this.p = new com.quizlet.data.repository.user.e();
        this.q = new androidx.camera.camera2.internal.compat.workaround.b();
    }

    public com.quizlet.infra.legacysyncengine.datasources.c a() {
        com.quizlet.infra.legacysyncengine.datasources.o oVar = (com.quizlet.infra.legacysyncengine.datasources.o) this.j;
        if (oVar != null) {
            return oVar;
        }
        Intrinsics.m("setDataSource");
        throw null;
    }

    public boolean b() {
        List list = (List) this.n;
        if (list != null && list.isEmpty()) {
            return false;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (((DBTerm) it2.next()).isIncomplete()) {
                return true;
            }
        }
        return false;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                StringBuilder sb = new StringBuilder("OTPCDetailsUIProperty{backgroundColor='");
                sb.append((String) this.b);
                sb.append("', lineBreakColor='");
                sb.append((String) this.c);
                sb.append("', toggleThumbColorOn='");
                sb.append((String) this.d);
                sb.append("', toggleThumbColorOff='");
                sb.append((String) this.e);
                sb.append("', toggleTrackColor='");
                sb.append((String) this.f);
                sb.append("', summaryTitleTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.h, sb, ", summaryTitleDescriptionTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.j, sb, ", consentTitleTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.k, sb, ", legitInterestTitleTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.l, sb, ", alwaysActiveTextProperty=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.m, sb, ", sdkListLinkProperty=");
                sb.append(((com.quizlet.data.repository.user.e) this.n).toString());
                sb.append(", vendorListLinkProperty=");
                sb.append(((com.quizlet.data.repository.user.e) this.o).toString());
                sb.append(", fullLegalTextLinkProperty=");
                sb.append(((com.quizlet.data.repository.user.e) this.p).toString());
                sb.append(", backIconProperty=");
                sb.append(((androidx.camera.camera2.internal.compat.workaround.b) this.q).toString());
                sb.append('}');
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public /* synthetic */ Zh(Yh yh) {
        this.a = 0;
        this.b = (HashSet) yh.d;
        this.c = (HashSet) yh.e;
        this.e = (HashSet) yh.g;
        this.f = (HashSet) yh.h;
        this.d = (HashSet) yh.f;
        this.g = (HashSet) yh.i;
        this.h = (HashSet) yh.b;
        this.i = (HashSet) yh.j;
        this.j = (HashSet) yh.m;
        this.k = (HashSet) yh.k;
        this.l = (HashSet) yh.l;
        this.m = (HashSet) yh.n;
        this.p = (C2411np) yh.p;
        this.n = (HashSet) yh.o;
        this.o = (HashSet) yh.c;
    }

    public Zh(com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, ExecutionRouter executionRouter, DatabaseHelper databaseHelper, com.quizlet.infra.legacysyncengine.managers.i uiModelSaveManager, com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a studySetChangeState, com.quizlet.quizletandroid.ui.setcreation.managers.p studySetLastEditTracker) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
        Intrinsics.checkNotNullParameter(databaseHelper, "databaseHelper");
        Intrinsics.checkNotNullParameter(uiModelSaveManager, "uiModelSaveManager");
        Intrinsics.checkNotNullParameter(studySetChangeState, "studySetChangeState");
        Intrinsics.checkNotNullParameter(studySetLastEditTracker, "studySetLastEditTracker");
        this.b = loader;
        this.c = syncDispatcher;
        this.d = executionRouter;
        this.e = databaseHelper;
        this.f = uiModelSaveManager;
        this.g = studySetChangeState;
        this.h = studySetLastEditTracker;
        this.n = kotlin.collections.K.a;
        this.o = com.google.android.gms.measurement.internal.Z.f("create(...)");
        this.p = com.google.android.gms.measurement.internal.Z.f("create(...)");
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.q = dVarZ;
    }
}

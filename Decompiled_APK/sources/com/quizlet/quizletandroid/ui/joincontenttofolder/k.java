package com.quizlet.quizletandroid.ui.joincontenttofolder;

import androidx.lifecycle.Y;
import com.braze.C1510p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.data.model.User;
import com.quizlet.db.data.caches.UserInfoCache;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends com.quizlet.viewmodel.b {
    public final com.quizlet.data.repository.searchexplanations.c c;
    public final com.quizlet.data.interactor.folderwithcreator.m d;
    public final com.quizlet.data.repository.widget.b e;
    public final androidx.work.impl.model.e f;
    public final androidx.work.impl.model.l g;
    public final UserInfoCache h;
    public final com.quizlet.features.notes.a i;
    public final com.quizlet.offline.managers.b j;
    public long k;
    public List l;
    public Long m;
    public List n;
    public ArrayList o;
    public List p;
    public final r q;
    public final Y r;
    public LinkedHashSet s;
    public final Y t;

    public k(com.quizlet.data.repository.searchexplanations.c getFolderSetsUseCase, com.quizlet.data.interactor.folderwithcreator.m getFoldersWithCreatorUseCase, com.quizlet.data.repository.widget.b updateFolderSetsUseCase, androidx.work.impl.model.e getClassFoldersUseCase, androidx.work.impl.model.l updateClassFoldersUseCase, UserInfoCache userInfoCache, com.quizlet.features.notes.a classContentLogger, com.quizlet.offline.managers.b offlineStateManager) {
        Intrinsics.checkNotNullParameter(getFolderSetsUseCase, "getFolderSetsUseCase");
        Intrinsics.checkNotNullParameter(getFoldersWithCreatorUseCase, "getFoldersWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(updateFolderSetsUseCase, "updateFolderSetsUseCase");
        Intrinsics.checkNotNullParameter(getClassFoldersUseCase, "getClassFoldersUseCase");
        Intrinsics.checkNotNullParameter(updateClassFoldersUseCase, "updateClassFoldersUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(classContentLogger, "classContentLogger");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        this.c = getFolderSetsUseCase;
        this.d = getFoldersWithCreatorUseCase;
        this.e = updateFolderSetsUseCase;
        this.f = getClassFoldersUseCase;
        this.g = updateClassFoldersUseCase;
        this.h = userInfoCache;
        this.i = classContentLogger;
        this.j = offlineStateManager;
        this.q = Z.f("create(...)");
        Y y = new Y();
        this.r = y;
        this.t = new Y();
        y.l(e.a);
    }

    public static final void B(k kVar, List list, ArrayList arrayList) {
        kVar.getClass();
        kVar.p = CollectionsKt.n0(list, new com.google.zxing.aztec.encoder.c(19));
        if (kVar.s == null) {
            kVar.s = CollectionsKt.z0(arrayList);
        }
        Y y = kVar.r;
        List list2 = kVar.p;
        if (list2 == null) {
            Intrinsics.m("allFoldersWithCreator");
            throw null;
        }
        LinkedHashSet linkedHashSet = kVar.s;
        if (linkedHashSet != null) {
            y.l(C(linkedHashSet, list2));
        } else {
            Intrinsics.m("selectedFolderIds");
            throw null;
        }
    }

    public static o C(LinkedHashSet linkedHashSet, List list) {
        com.quizlet.quizletandroid.ui.joincontenttofolder.models.d dVar;
        timber.log.c.a.g("Updating selected folder state for UI...", new Object[0]);
        List listB = A.b(new com.quizlet.quizletandroid.ui.joincontenttofolder.models.a());
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            CreatedFolderWithCreator createdFolderWithCreator = (CreatedFolderWithCreator) it2.next();
            CreatedFolder createdFolder = createdFolderWithCreator.a;
            User user = createdFolderWithCreator.b;
            if (user != null) {
                int iB = AbstractC3179j6.b(user);
                boolean z = user.e;
                dVar = new com.quizlet.quizletandroid.ui.joincontenttofolder.models.d(user.i, iB, user.b, z);
            } else {
                dVar = null;
            }
            arrayList.add(new com.quizlet.quizletandroid.ui.joincontenttofolder.models.b(createdFolder, dVar, linkedHashSet.contains(Long.valueOf(createdFolder.a()))));
        }
        return new o(CollectionsKt.c0(listB, arrayList));
    }

    public final void D() {
        Long l = this.m;
        boolean z = l != null;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        com.quizlet.data.interactor.folderwithcreator.m mVar = this.d;
        r stopToken = this.q;
        if (z) {
            if (l == null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            long jLongValue = l.longValue();
            timber.log.c.a.g("Fetching ClassFolders and Folders with Creators...", new Object[0]);
            androidx.work.impl.model.e eVar = this.f;
            eVar.getClass();
            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
            io.reactivex.rxjava3.core.i iVarY = io.reactivex.rxjava3.core.i.y(((androidx.work.impl.model.c) eVar.c).b(stopToken, new C1510p(eVar, jLongValue, 4)), mVar.i(A.b(Long.valueOf(this.k)), stopToken), new i(0));
            Intrinsics.checkNotNullExpressionValue(iVarY, "Observable.zip(source1, …ombineFunction(t1, t2) })");
            io.reactivex.rxjava3.disposables.b bVarU = iVarY.u(new h(this, 2), new h(this, 3), bVar);
            Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
            Intrinsics.checkNotNullParameter(bVarU, "<this>");
            A(bVarU);
            return;
        }
        List setIds = this.l;
        if (setIds == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        timber.log.c.a.g("Fetching FolderSets and Folders with Creators...", new Object[0]);
        com.quizlet.data.repository.searchexplanations.c cVar = this.c;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        io.reactivex.rxjava3.core.i iVarY2 = io.reactivex.rxjava3.core.i.y(((androidx.work.impl.model.c) cVar.c).b(stopToken, new com.braze.triggers.managers.h(24, cVar, setIds)), mVar.i(A.b(Long.valueOf(this.k)), stopToken), new j(0));
        Intrinsics.checkNotNullExpressionValue(iVarY2, "Observable.zip(source1, …ombineFunction(t1, t2) })");
        io.reactivex.rxjava3.disposables.b bVarU2 = iVarY2.u(new h(this, 4), new h(this, 5), bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU2, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU2, "<this>");
        A(bVarU2);
    }

    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        this.q.onSuccess(Unit.a);
    }
}

package com.quizlet.remote.model.union.folderwithcreatorinclass;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.interactor.progress.c;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.User;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.union.folderwithcreatorinclass.FolderWithCreatorInClassResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ c a;

    public a(c cVar) {
        this.a = cVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.util.ArrayList] */
    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List listF;
        Map mapC;
        ?? arrayList;
        List<RemoteFolder> list;
        List remotes;
        List remotes2;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        FolderWithCreatorInClassResponse folderWithCreatorInClassResponse = (FolderWithCreatorInClassResponse) response.a();
        FolderWithCreatorInClassResponse.Models models = folderWithCreatorInClassResponse != null ? folderWithCreatorInClassResponse.d : null;
        c cVar = this.a;
        if (models == null || (remotes2 = models.a) == null) {
            listF = K.a;
        } else {
            com.quizlet.quizletandroid.ui.folder.logging.a aVar = (com.quizlet.quizletandroid.ui.folder.logging.a) cVar.b;
            Intrinsics.checkNotNullParameter(remotes2, "remotes");
            listF = S.f(aVar, remotes2);
        }
        if (models == null || (remotes = models.c) == null) {
            mapC = V.c();
        } else {
            com.quizlet.quizletandroid.ui.activitycenter.models.a aVar2 = (com.quizlet.quizletandroid.ui.activitycenter.models.a) cVar.d;
            Intrinsics.checkNotNullParameter(remotes, "remotes");
            ArrayList arrayListF = S.f(aVar2, remotes);
            int iA = U.a(C.q(arrayListF, 10));
            if (iA < 16) {
                iA = 16;
            }
            mapC = new LinkedHashMap(iA);
            Iterator it2 = arrayListF.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                mapC.put(Long.valueOf(((User) next).a), next);
            }
        }
        if (models == null || (list = models.b) == null) {
            arrayList = K.a;
        } else {
            arrayList = new ArrayList(C.q(list, 10));
            for (RemoteFolder remoteFolder : list) {
                arrayList.add(new C4132h0(((com.quizlet.quizletandroid.ui.folder.logging.a) cVar.c).g(remoteFolder), (User) mapC.get(remoteFolder.c)));
            }
        }
        return new com.quizlet.data.repository.folderwithcreatorinclass.a(listF, arrayList);
    }
}

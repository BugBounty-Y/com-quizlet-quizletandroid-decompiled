package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.union.folderwithcreator.FolderWithCreatorResponse;
import com.quizlet.remote.model.user.RemoteUser;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements h {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Iterable] */
    /* JADX WARN: Type inference failed for: r2v5, types: [java.util.ArrayList] */
    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Map mapC;
        ?? arrayList;
        List<RemoteFolder> list;
        List list2;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        FolderWithCreatorResponse folderWithCreatorResponse = (FolderWithCreatorResponse) response.a();
        FolderWithCreatorResponse.Models models = folderWithCreatorResponse != null ? folderWithCreatorResponse.d : null;
        if (models == null || (list2 = models.b) == null) {
            mapC = V.c();
        } else {
            int iA = U.a(C.q(list2, 10));
            if (iA < 16) {
                iA = 16;
            }
            mapC = new LinkedHashMap(iA);
            for (Object obj2 : list2) {
                mapC.put(Long.valueOf(((RemoteUser) obj2).a), obj2);
            }
        }
        if (models == null || (list = models.a) == null) {
            arrayList = K.a;
        } else {
            arrayList = new ArrayList(C.q(list, 10));
            for (RemoteFolder remoteFolder : list) {
                arrayList.add(new f(remoteFolder, (RemoteUser) mapC.get(remoteFolder.c)));
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        int i = 0;
        for (Object obj3 : arrayList) {
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            arrayList2.add((f) obj3);
            i = i2;
        }
        return arrayList2;
    }
}

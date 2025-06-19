package com.quizlet.remote.model.folderset;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folderset.FolderSetResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ com.quizlet.data.repository.explanations.myexplanations.a a;
    public final /* synthetic */ ArrayList b;

    public a(com.quizlet.data.repository.explanations.myexplanations.a aVar, ArrayList arrayList) {
        this.a = aVar;
        this.b = arrayList;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        FolderSetResponse.Models models;
        List list;
        RemoteFolderSet remoteFolderSet;
        Long l;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        FolderSetResponse folderSetResponse = (FolderSetResponse) response.a();
        if (folderSetResponse == null || (models = folderSetResponse.d) == null || (list = models.a) == null) {
            return K.a;
        }
        ArrayList remotes = new ArrayList(C.q(list, 10));
        int i = 0;
        for (Object obj2 : list) {
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            RemoteFolderSet remoteFolderSet2 = (RemoteFolderSet) obj2;
            ArrayList arrayList = this.b;
            if (arrayList != null && (remoteFolderSet = (RemoteFolderSet) arrayList.get(i)) != null && (l = remoteFolderSet.a) != null) {
                RemoteFolderSet remoteFolderSetCopy = remoteFolderSet2.copy(Long.valueOf(l.longValue()), remoteFolderSet2.b, remoteFolderSet2.c, remoteFolderSet2.d, remoteFolderSet2.e, remoteFolderSet2.f, remoteFolderSet2.g, remoteFolderSet2.h);
                if (remoteFolderSetCopy != null) {
                    remoteFolderSet2 = remoteFolderSetCopy;
                }
            }
            remotes.add(remoteFolderSet2);
            i = i2;
        }
        j jVar = (j) this.a.c;
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        return S.f(jVar, remotes);
    }
}

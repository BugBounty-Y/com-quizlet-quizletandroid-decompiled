package com.quizlet.remote.model.folder;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.folder.FolderResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ p a;
    public final /* synthetic */ ArrayList b;

    public o(p pVar, ArrayList arrayList) {
        this.a = pVar;
        this.b = arrayList;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        FolderResponse.Models models;
        List list;
        Long l;
        RemoteFolder remoteFolderA;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        FolderResponse folderResponse = (FolderResponse) response.a();
        if (folderResponse == null || (models = folderResponse.d) == null || (list = models.a) == null) {
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
            RemoteFolder remoteFolder = (RemoteFolder) obj2;
            RemoteFolder remoteFolder2 = (RemoteFolder) this.b.get(i);
            if (remoteFolder2 != null && (l = remoteFolder2.b) != null && (remoteFolderA = RemoteFolder.a(remoteFolder, Long.valueOf(l.longValue()), null, null, 1048573)) != null) {
                remoteFolder = remoteFolderA;
            }
            remotes.add(remoteFolder);
            i = i2;
        }
        com.quizlet.quizletandroid.ui.folder.logging.a aVar = this.a.b;
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        return S.f(aVar, remotes);
    }
}

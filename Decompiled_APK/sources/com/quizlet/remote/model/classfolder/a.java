package com.quizlet.remote.model.classfolder;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.repository.widget.b;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.classfolder.ClassFolderResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ b a;
    public final /* synthetic */ ArrayList b;

    public a(b bVar, ArrayList arrayList) {
        this.a = bVar;
        this.b = arrayList;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ClassFolderResponse.Models models;
        List list;
        RemoteClassFolder remoteClassFolder;
        a aVar = this;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        ClassFolderResponse classFolderResponse = (ClassFolderResponse) response.a();
        if (classFolderResponse == null || (models = classFolderResponse.d) == null || (list = models.a) == null) {
            return K.a;
        }
        b bVar = aVar.a;
        bVar.getClass();
        ArrayList remotes = new ArrayList(C.q(list, 10));
        int i = 0;
        for (Object obj2 : list) {
            int i2 = i + 1;
            Long l = null;
            if (i < 0) {
                B.p();
                throw null;
            }
            RemoteClassFolder remoteClassFolder2 = (RemoteClassFolder) obj2;
            ArrayList arrayList = aVar.b;
            if (arrayList != null && (remoteClassFolder = (RemoteClassFolder) arrayList.get(i)) != null) {
                l = remoteClassFolder.a;
            }
            Long l2 = l;
            if (l2 != null) {
                RemoteClassFolder remoteClassFolderCopy = remoteClassFolder2.copy(l2, remoteClassFolder2.b, remoteClassFolder2.c, remoteClassFolder2.d, remoteClassFolder2.e, remoteClassFolder2.f, remoteClassFolder2.g, remoteClassFolder2.h, remoteClassFolder2.i);
                if (remoteClassFolderCopy != null) {
                    remoteClassFolder2 = remoteClassFolderCopy;
                }
            }
            remotes.add(remoteClassFolder2);
            aVar = this;
            i = i2;
        }
        com.quizlet.quizletandroid.ui.folder.logging.a aVar2 = (com.quizlet.quizletandroid.ui.folder.logging.a) bVar.c;
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        return S.f(aVar2, remotes);
    }
}

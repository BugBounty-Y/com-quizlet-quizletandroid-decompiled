package com.quizlet.remote.model.foldertoadd;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.C4169u;
import com.quizlet.remote.model.foldertoadd.FolderToAddMaterialResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.remote.mapper.base.a {
    public static List a(FolderToAddMaterialResponse remote) {
        FolderToAddMaterialResponse.FolderToAddData folderToAddData;
        List<FolderToAddMaterialResponse.FolderToAddModel> list;
        Intrinsics.checkNotNullParameter(remote, "remote");
        List list2 = remote.d;
        if (list2 == null || (folderToAddData = (FolderToAddMaterialResponse.FolderToAddData) CollectionsKt.L(list2)) == null || (list = folderToAddData.a) == null) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (FolderToAddMaterialResponse.FolderToAddModel folderToAddModel : list) {
            long j = folderToAddModel.a;
            Iterable<FolderToAddMaterialResponse.FolderToAddModel> iterable = folderToAddModel.d;
            if (iterable == null) {
                iterable = K.a;
            }
            ArrayList arrayList2 = new ArrayList(C.q(iterable, 10));
            for (FolderToAddMaterialResponse.FolderToAddModel folderToAddModel2 : iterable) {
                arrayList2.add(new C4169u(folderToAddModel2.a, folderToAddModel2.b, folderToAddModel2.c, null));
            }
            arrayList.add(new C4169u(j, folderToAddModel.b, folderToAddModel.c, arrayList2));
        }
        return arrayList;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final /* bridge */ /* synthetic */ Object c(Object obj) {
        return a((FolderToAddMaterialResponse) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return S.f(this, list);
    }
}

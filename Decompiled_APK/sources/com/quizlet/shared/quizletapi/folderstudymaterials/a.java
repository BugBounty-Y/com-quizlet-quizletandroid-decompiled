package com.quizlet.shared.quizletapi.folderstudymaterials;

import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.httpclient.e;
import com.quizlet.shared.models.api.base.ModelWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByFolderId;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByFolderIdAndType;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByStudyMaterialIdAndType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends com.quizlet.shared.quizletapi.base.c implements b {
    public final com.quizlet.shared.quizletapi.b c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json, com.quizlet.shared.quizletapi.b quizletApi) {
        super(httpClient, json);
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
        this.c = quizletApi;
    }

    @Override // com.quizlet.shared.quizletapi.base.c
    public final e b(Object obj) {
        com.quizlet.shared.models.api.folderstudymaterials.a key = (com.quizlet.shared.models.api.folderstudymaterials.a) obj;
        Intrinsics.checkNotNullParameter(key, "key");
        String strA = com.quizlet.shared.quizletapi.b.a(this.c, "folder-study-materials", null, 14);
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        if (!key.j().isEmpty()) {
            linkedHashMap.put("filters[folderId]", S4.f(key.j()));
        }
        if (key.k()) {
            linkedHashMap.put("include[folderStudyMaterial][folder]", "user");
            linkedHashMap.put("include[folderStudyMaterial][set]", AssociationNames.CREATOR);
        }
        linkedHashMap.put("filters[isDeleted]", "false");
        linkedHashMap.put("perPage", "500");
        if (!(key instanceof GetFolderStudyMaterialsByFolderId)) {
            if (key instanceof GetFolderStudyMaterialsByFolderIdAndType) {
                List list = ((GetFolderStudyMaterialsByFolderIdAndType) key).c;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((p) it2.next()).a));
                }
                linkedHashMap = V.h(linkedHashMap, U.b(new Pair("filters[studyMaterialType]", S4.f(arrayList))));
            } else {
                if (!(key instanceof GetFolderStudyMaterialsByStudyMaterialIdAndType)) {
                    throw new NoWhenBranchMatchedException();
                }
                GetFolderStudyMaterialsByStudyMaterialIdAndType getFolderStudyMaterialsByStudyMaterialIdAndType = (GetFolderStudyMaterialsByStudyMaterialIdAndType) key;
                linkedHashMap = V.h(linkedHashMap, V.f(new Pair("filters[studyMaterialId]", getFolderStudyMaterialsByStudyMaterialIdAndType.b), new Pair("filters[studyMaterialType]", String.valueOf(getFolderStudyMaterialsByStudyMaterialIdAndType.c.a))));
            }
        }
        return new e(strA, linkedHashMap, null, com.quizlet.shared.httpclient.d.a, 4);
    }

    @Override // com.quizlet.shared.quizletapi.base.c
    public final Object e(QuizletApiThreeResponse quizletApiThreeResponse) {
        ModelWrapper modelWrapper;
        if (quizletApiThreeResponse == null || (modelWrapper = quizletApiThreeResponse.a) == null) {
            return null;
        }
        return new com.quizlet.shared.models.api.folderstudymaterials.b(modelWrapper.d, modelWrapper.l, modelWrapper.f, modelWrapper.c, modelWrapper.j, modelWrapper.k, modelWrapper.b, modelWrapper.h);
    }
}

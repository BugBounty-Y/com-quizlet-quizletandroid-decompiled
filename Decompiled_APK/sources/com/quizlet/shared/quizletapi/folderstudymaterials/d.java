package com.quizlet.shared.quizletapi.folderstudymaterials;

import com.quizlet.shared.httpclient.e;
import com.quizlet.shared.models.api.base.ModelWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.folderstudymaterials.CreateFolderStudyMaterialsRequest;
import com.quizlet.shared.models.api.folderstudymaterials.DeleteFolderStudyMaterialsRequest;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends com.quizlet.shared.quizletapi.base.c implements c {
    public final kotlinx.serialization.json.c c;
    public final com.quizlet.shared.quizletapi.b d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.remote.kmp.a httpClient, kotlinx.serialization.json.c json, com.quizlet.shared.quizletapi.b quizletApi) {
        super(httpClient, json);
        Intrinsics.checkNotNullParameter(httpClient, "httpClient");
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(quizletApi, "quizletApi");
        this.c = json;
        this.d = quizletApi;
    }

    @Override // com.quizlet.shared.quizletapi.base.c
    public final e b(Object obj) {
        String str;
        String strC;
        com.quizlet.shared.httpclient.d dVar;
        com.quizlet.shared.models.api.folderstudymaterials.c key = (com.quizlet.shared.models.api.folderstudymaterials.c) obj;
        Intrinsics.checkNotNullParameter(key, "key");
        boolean z = key instanceof CreateFolderStudyMaterialsRequest;
        if (z) {
            str = "save";
        } else {
            if (!(key instanceof DeleteFolderStudyMaterialsRequest)) {
                throw new NoWhenBranchMatchedException();
            }
            str = null;
        }
        String strA = com.quizlet.shared.quizletapi.b.a(this.d, "folder-study-materials", str, 12);
        kotlinx.serialization.json.c cVar = this.c;
        if (z) {
            strC = cVar.c(CreateFolderStudyMaterialsRequest.Companion.serializer(), key);
        } else {
            if (!(key instanceof DeleteFolderStudyMaterialsRequest)) {
                throw new NoWhenBranchMatchedException();
            }
            strC = cVar.c(DeleteFolderStudyMaterialsRequest.Companion.serializer(), key);
        }
        String str2 = strC;
        if (z) {
            dVar = com.quizlet.shared.httpclient.d.b;
        } else {
            if (!(key instanceof DeleteFolderStudyMaterialsRequest)) {
                throw new NoWhenBranchMatchedException();
            }
            dVar = com.quizlet.shared.httpclient.d.c;
        }
        return new e(strA, null, str2, dVar, 2);
    }

    @Override // com.quizlet.shared.quizletapi.base.c
    public final Object e(QuizletApiThreeResponse quizletApiThreeResponse) {
        ModelWrapper modelWrapper;
        if (quizletApiThreeResponse == null || (modelWrapper = quizletApiThreeResponse.a) == null) {
            return null;
        }
        return modelWrapper.d;
    }
}

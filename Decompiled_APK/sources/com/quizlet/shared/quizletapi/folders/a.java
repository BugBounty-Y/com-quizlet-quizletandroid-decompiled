package com.quizlet.shared.quizletapi.folders;

import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.quizlet.shared.httpclient.d;
import com.quizlet.shared.httpclient.e;
import com.quizlet.shared.models.api.base.ModelWrapper;
import com.quizlet.shared.models.api.base.QuizletApiThreeResponse;
import com.quizlet.shared.models.api.folders.GetFoldersById;
import com.quizlet.shared.models.api.folders.GetFoldersByUserIds;
import com.quizlet.shared.quizletapi.base.c;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends c implements b {
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
        String strF;
        Map mapD;
        com.quizlet.shared.models.api.folders.a key = (com.quizlet.shared.models.api.folders.a) obj;
        Intrinsics.checkNotNullParameter(key, "key");
        boolean z = key instanceof GetFoldersById;
        if (!(z ? true : key instanceof GetFoldersByUserIds)) {
            throw new NoWhenBranchMatchedException();
        }
        if (z) {
            strF = S4.f(((GetFoldersById) key).b);
        } else {
            if (!(key instanceof GetFoldersByUserIds)) {
                throw new NoWhenBranchMatchedException();
            }
            strF = null;
        }
        String strA = com.quizlet.shared.quizletapi.b.a(this.c, "folders", strF, 12);
        key.getClass();
        Map mapD2 = T4.d(new Pair("filters[isDeleted]", Boolean.FALSE.toString()), new Pair("filters[isHidden]", "false"));
        if (key instanceof GetFoldersById) {
            mapD = T4.d(new Pair("include[folder]", ((GetFoldersById) key).c ? "user" : null));
        } else {
            if (!(key instanceof GetFoldersByUserIds)) {
                throw new NoWhenBranchMatchedException();
            }
            mapD = T4.d(new Pair("include[folder]", "user"), new Pair("filters[personId]", S4.f(((GetFoldersByUserIds) key).b)));
        }
        return new e(strA, V.h(mapD2, mapD), null, d.a);
    }

    @Override // com.quizlet.shared.quizletapi.base.c
    public final Object e(QuizletApiThreeResponse quizletApiThreeResponse) {
        ModelWrapper modelWrapper;
        if (quizletApiThreeResponse == null || (modelWrapper = quizletApiThreeResponse.a) == null) {
            return null;
        }
        return new com.quizlet.shared.models.api.folders.b(modelWrapper.c, modelWrapper.l);
    }
}

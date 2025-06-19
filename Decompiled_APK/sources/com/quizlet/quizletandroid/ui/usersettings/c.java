package com.quizlet.quizletandroid.ui.usersettings;

import androidx.camera.camera2.internal.j0;
import androidx.compose.foundation.text.input.internal.u;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.db.data.caches.UserInfoCacheKt;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.infra.legacysyncengine.tasks.parse.f;
import com.quizlet.infra.legacysyncengine.tasks.parse.h;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ c(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                d dVar = this.b;
                dVar.getClass();
                com.quizlet.infra.legacysyncengine.net.constants.a aVar = com.quizlet.infra.legacysyncengine.net.constants.a.b;
                ModelType<DBUser> modelType = Models.USER;
                f fVar = dVar.f;
                fVar.getClass();
                h hVarA = new j0(fVar, (Object) null, modelType, aVar).a((ApiThreeWrapper) obj);
                s sVar = dVar.e;
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar2 = (com.quizlet.infra.legacysyncengine.net.listeners.d) sVar.d;
                u uVar = (u) sVar.f;
                ExecutionRouter executionRouter = (ExecutionRouter) sVar.e;
                executionRouter.d(new com.quizlet.infra.legacysyncengine.net.importer.a(new s(executionRouter, (DatabaseHelper) sVar.b, (ModelIdentityProvider) sVar.c, dVar2, uVar, hVarA, null, aVar), 0));
                break;
            default:
                ApiResponse apiResponse = (ApiResponse) obj;
                d dVar3 = this.b;
                dVar3.getClass();
                if (apiResponse.getDataWrapper() != null && ((DataWrapper) apiResponse.getDataWrapper()).getAuthentication() != null) {
                    String accessToken = ((DataWrapper) apiResponse.getDataWrapper()).getAuthentication().getAccessToken();
                    UserInfoCacheKt.a(dVar3.g, dVar3.i.r);
                    dVar3.h.b(accessToken);
                    break;
                }
                break;
        }
    }
}

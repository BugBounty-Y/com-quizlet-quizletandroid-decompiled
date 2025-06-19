package com.quizlet.features.setpage.utils.setpermissions;

import androidx.work.impl.model.n;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.setpage.header.ui.g;
import com.quizlet.features.setpage.usecases.i;
import com.quizlet.infra.legacysyncengine.managers.h;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.o;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class f implements a {
    public final UserInfoCache a;
    public final ObjectWriter b;
    public final h c;
    public final n d;
    public final IQuizletApiClient e;
    public final o f;
    public final o g;

    public f(UserInfoCache userInfoCache, ObjectWriter objectWriter, h serverModelSaveManager, n permissions, IQuizletApiClient quizletApiClient, o networkScheduler, o mainScheduler) {
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(objectWriter, "objectWriter");
        Intrinsics.checkNotNullParameter(serverModelSaveManager, "serverModelSaveManager");
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainScheduler, "mainScheduler");
        this.a = userInfoCache;
        this.b = objectWriter;
        this.c = serverModelSaveManager;
        this.d = permissions;
        this.e = quizletApiClient;
        this.f = networkScheduler;
        this.g = mainScheduler;
    }

    public final io.reactivex.rxjava3.internal.operators.completable.a a(DBStudySet set, com.quizlet.baseui.base.b activity, Function1 onLoadSetPage) {
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(onLoadSetPage, "onLoadSetPage");
        return b(set, activity, false, R.string.no_password_view_exception, R.string.set_permission_error, new g(2, onLoadSetPage, set), null);
    }

    public final io.reactivex.rxjava3.internal.operators.completable.a b(DBStudySet set, com.quizlet.baseui.base.b activity, boolean z, int i, int i2, Function1 onPermissionGranted, q qVar) {
        io.reactivex.rxjava3.internal.operators.flowable.b bVarE;
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(onPermissionGranted, "onPermissionGranted");
        n nVar = this.d;
        AbstractC5040y abstractC5040y = (AbstractC5040y) nVar.a;
        if (z) {
            Intrinsics.checkNotNullParameter(set, "set");
            bVarE = L1.e(abstractC5040y, new com.quizlet.features.setpage.usecases.h(nVar, set, null));
        } else {
            Intrinsics.checkNotNullParameter(set, "set");
            bVarE = L1.e(abstractC5040y, new i(nVar, set, null));
        }
        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(5, bVarE.h(this.g), new C2537qm(onPermissionGranted, this, activity, set, i, qVar, i2));
        Intrinsics.checkNotNullExpressionValue(aVar, "flatMapCompletable(...)");
        return aVar;
    }
}

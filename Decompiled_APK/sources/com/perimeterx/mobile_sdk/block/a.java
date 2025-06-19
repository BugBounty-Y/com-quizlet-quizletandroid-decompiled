package com.perimeterx.mobile_sdk.block;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import androidx.work.I;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3744v4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F4;
import com.perimeterx.mobile_sdk.session.l;
import com.perimeterx.mobile_sdk.session.m;
import com.perimeterx.mobile_sdk.session.q;
import java.util.HashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlinx.coroutines.E;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public com.perimeterx.mobile_sdk.session.d a;

    public final void a(PXBlockActivity activity) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        HashMap map = PXBlockActivity.e;
        O.c(map).remove(activity.c);
        activity.finish();
        com.perimeterx.mobile_sdk.session.d dVar = this.a;
        if (dVar != null) {
            E.A(E.c(kotlinx.coroutines.O.a), null, null, new q(dVar, false, null), 3);
            m mVar = dVar.b;
            String str = mVar.a;
            new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.session.c(mVar.c, str, 0));
        }
    }

    public final void b(b blockMetaData, String str) {
        Application application;
        Intrinsics.checkNotNullParameter(blockMetaData, "blockMetaData");
        l lVar = l.a;
        Application application2 = l.b;
        if (application2 != null) {
            new Handler(Looper.getMainLooper()).post(new I((Object) this, (Object) application2, blockMetaData.a(), (Object) blockMetaData, (Object) str, 4));
            return;
        }
        HashMap userInfo = V.e(new Pair(com.perimeterx.mobile_sdk.logger.c.a.a(), "failed to show block activity - missing context"));
        Intrinsics.checkNotNullParameter(userInfo, "userInfo");
        String str2 = F4.a;
        if (str2 == null || (application = l.b) == null) {
            return;
        }
        JSONObject jSONObject = new JSONObject();
        for (Map.Entry entry : userInfo.entrySet()) {
            jSONObject.putOpt((String) entry.getKey(), (String) entry.getValue());
        }
        E.A(E.c(kotlinx.coroutines.O.a), null, null, new com.perimeterx.mobile_sdk.logger.a(str2, jSONObject, new com.quizlet.data.interactor.set.c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(application), AbstractC3744v4.a(application), null), 3);
    }
}

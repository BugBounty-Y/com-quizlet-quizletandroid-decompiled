package com.quizlet.quizletandroid.logging.ga;

import android.os.Bundle;
import com.comscore.android.id.IdHelperAndroid;
import com.google.android.gms.analytics.c;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.functions.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final /* synthetic */ com.quizlet.data.repository.user.a a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ Long d;
    public final /* synthetic */ G1 e;
    public final /* synthetic */ A1 f;

    public a(com.quizlet.data.repository.user.a aVar, String str, String str2, Long l, G1 g1, A1 a1) {
        this.a = aVar;
        this.b = str;
        this.c = str2;
        this.d = l;
        this.e = g1;
        this.f = a1;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        LoggedInUserStatus userStatus = (LoggedInUserStatus) obj;
        Intrinsics.checkNotNullParameter(userStatus, "userStatus");
        Bundle bundle = new Bundle();
        bundle.putString("screenName", this.b);
        bundle.putString("isLoggedIn", String.valueOf(userStatus.isLoggedIn()));
        com.quizlet.data.repository.user.a aVar = this.a;
        bundle.putString("clientId", ((c) aVar.c).a());
        String str = this.c;
        if (str == null) {
            str = IdHelperAndroid.NO_ID_AVAILABLE;
        }
        bundle.putString("studyableTitle", str);
        bundle.putString(DBUserStudyableFields.Names.STUDYABLE_ID, String.valueOf(this.d));
        bundle.putString(DBUserStudyableFields.Names.STUDYABLE_TYPE, String.valueOf(this.e));
        bundle.putString("studyMode", String.valueOf(this.f));
        if (userStatus.getPersonId() == 0) {
            bundle.putString("userId", null);
        } else {
            bundle.putString("userId", String.valueOf(userStatus.getPersonId()));
        }
        ((FirebaseAnalytics) aVar.d).a(bundle, "screenLoad");
    }
}

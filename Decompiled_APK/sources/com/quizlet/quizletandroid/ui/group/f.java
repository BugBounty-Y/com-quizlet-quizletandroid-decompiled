package com.quizlet.quizletandroid.ui.group;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.util.ApiThreeWrapperUtil;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import java.util.HashSet;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class f implements io.reactivex.rxjava3.functions.b, io.reactivex.rxjava3.functions.h {
    public static final f a = new f();
    public static final f b = new f();

    public static Intent a(Context context, Long l, Uri uri, boolean z, String str) {
        Intent intentB = AbstractC4178x.b(context, "context", context, GroupActivity.class);
        if (uri == null && l == null) {
            throw new IllegalStateException("No class id or uri provided.");
        }
        if (l != null) {
            intentB.putExtra(DBGroupMembershipFields.Names.CLASS_ID, l.longValue());
        }
        if (z) {
            intentB.putExtra("autoJoinCode", str);
            intentB.putExtra("shouldShowJoinButton", true);
        }
        if (uri != null) {
            intentB.setAction("android.intent.action.VIEW");
            intentB.setData(uri);
        }
        return intentB;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        List api = (List) obj;
        List database = (List) obj2;
        Intrinsics.checkNotNullParameter(api, "api");
        Intrinsics.checkNotNullParameter(database, "database");
        HashSet hashSet = new HashSet();
        hashSet.addAll(api);
        hashSet.addAll(database);
        return hashSet;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        K response = (K) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        return ApiThreeWrapperUtil.a((ApiThreeWrapper) response.b);
    }
}

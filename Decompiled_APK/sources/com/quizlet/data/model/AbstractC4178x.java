package com.quizlet.data.model;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.util.TypedValue;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import com.comscore.streaming.EventType;
import com.j256.ormlite.field.DatabaseFieldConfig;
import com.j256.ormlite.table.DatabaseTableConfig;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.x, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract /* synthetic */ class AbstractC4178x {
    public static int a(float f, int i) {
        return kotlin.math.c.b(TypedValue.applyDimension(i, f, Resources.getSystem().getDisplayMetrics()));
    }

    public static Intent b(Context context, String str, Context context2, Class cls) {
        Intrinsics.checkNotNullParameter(context, str);
        return new Intent(context2, (Class<?>) cls);
    }

    public static DatabaseFieldConfig c(DatabaseFieldConfig databaseFieldConfig, int i, ArrayList arrayList, DatabaseFieldConfig databaseFieldConfig2, String str) {
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(i);
        arrayList.add(databaseFieldConfig2);
        DatabaseFieldConfig databaseFieldConfig3 = new DatabaseFieldConfig();
        databaseFieldConfig3.setFieldName(str);
        return databaseFieldConfig3;
    }

    public static DatabaseFieldConfig d(DatabaseFieldConfig databaseFieldConfig, String str, int i, ArrayList arrayList, DatabaseFieldConfig databaseFieldConfig2) {
        databaseFieldConfig.setFieldName(str);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(i);
        arrayList.add(databaseFieldConfig2);
        return new DatabaseFieldConfig();
    }

    public static DatabaseFieldConfig e(String str, String str2, boolean z, int i, ArrayList arrayList) {
        DatabaseFieldConfig databaseFieldConfig = new DatabaseFieldConfig();
        databaseFieldConfig.setFieldName(str);
        databaseFieldConfig.setColumnName(str2);
        databaseFieldConfig.setId(z);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(i);
        arrayList.add(databaseFieldConfig);
        return new DatabaseFieldConfig();
    }

    public static DatabaseFieldConfig f(ArrayList arrayList, DatabaseFieldConfig databaseFieldConfig, String str, String str2, int i) {
        arrayList.add(databaseFieldConfig);
        DatabaseFieldConfig databaseFieldConfig2 = new DatabaseFieldConfig();
        databaseFieldConfig2.setFieldName(str);
        databaseFieldConfig2.setColumnName(str2);
        databaseFieldConfig2.setMaxForeignAutoRefreshLevel(i);
        arrayList.add(databaseFieldConfig2);
        return new DatabaseFieldConfig();
    }

    public static DatabaseTableConfig g(Class cls, String str) {
        DatabaseTableConfig databaseTableConfig = new DatabaseTableConfig();
        databaseTableConfig.setDataClass(cls);
        databaseTableConfig.setTableName(str);
        return databaseTableConfig;
    }

    public static com.onetrust.otpublishers.headless.UI.adapter.s h(String str) {
        com.onetrust.otpublishers.headless.UI.adapter.s sVar = new com.onetrust.otpublishers.headless.UI.adapter.s(2);
        Intrinsics.checkNotNullParameter(sVar, str);
        return sVar;
    }

    public static com.quizlet.data.repository.user.a i(com.quizlet.infra.contracts.growthbook.a aVar, String str, String str2, com.quizlet.infra.contracts.growthbook.a aVar2) {
        Intrinsics.checkNotNullParameter(aVar, str);
        return new com.quizlet.data.repository.user.a(str2, aVar2);
    }

    public static dagger.internal.c j(com.quizlet.quizletandroid.u uVar, int i) {
        return dagger.internal.a.b(new com.quizlet.quizletandroid.t(uVar, i));
    }

    public static Object k(Unit unit, Function2 function2, C0814p c0814p, boolean z, InterfaceC0773a0 interfaceC0773a0) {
        C0776c.f(c0814p, unit, function2);
        c0814p.p(z);
        return interfaceC0773a0.getValue();
    }

    public static Object l(retrofit2.L l, String str, retrofit2.L l2, String str2, Class cls) {
        Intrinsics.checkNotNullParameter(l, str);
        Intrinsics.checkNotNullParameter(l2, str2);
        return l.b(cls);
    }

    public static String m(int i, String str, String str2) {
        StringBuilder sb = new StringBuilder(i);
        sb.append(str);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, str2);
        return string;
    }

    public static org.koin.core.definition.d n(org.koin.core.module.a aVar, org.koin.core.instance.a aVar2, org.koin.core.module.a aVar3, org.koin.core.instance.a aVar4, String str) {
        aVar.b(aVar2);
        org.koin.core.definition.d dVar = new org.koin.core.definition.d(aVar3, aVar4);
        Intrinsics.checkNotNullParameter(dVar, str);
        return dVar;
    }

    public static org.slf4j.b o(org.slf4j.a aVar, String str, Class cls, String str2) {
        Intrinsics.checkNotNullParameter(aVar, str);
        org.slf4j.b bVarA = aVar.a(cls.getSimpleName());
        Intrinsics.checkNotNullExpressionValue(bVarA, str2);
        return bVarA;
    }

    public static void p(int i, com.squareup.moshi.l lVar, com.squareup.moshi.w wVar, String str) {
        lVar.g(wVar, Integer.valueOf(i));
        wVar.l(str);
    }

    public static void q(DatabaseFieldConfig databaseFieldConfig, String str, String str2, int i) {
        databaseFieldConfig.setFieldName(str);
        databaseFieldConfig.setColumnName(str2);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(i);
    }

    public static boolean r(C0814p c0814p, boolean z, int i, InterfaceC0773a0 interfaceC0773a0) {
        c0814p.p(z);
        c0814p.X(i);
        return c0814p.f(interfaceC0773a0);
    }

    public static boolean s(C0814p c0814p, boolean z, int i, Function1 function1) {
        c0814p.p(z);
        c0814p.X(i);
        return c0814p.f(function1);
    }

    public static DatabaseFieldConfig t(DatabaseFieldConfig databaseFieldConfig, int i, ArrayList arrayList, DatabaseFieldConfig databaseFieldConfig2, String str) {
        databaseFieldConfig.setColumnName(str);
        databaseFieldConfig.setMaxForeignAutoRefreshLevel(i);
        arrayList.add(databaseFieldConfig2);
        return new DatabaseFieldConfig();
    }

    public static /* synthetic */ String u(int i) {
        switch (i) {
            case 1:
                return "READER";
            case 2:
                return "EDITOR";
            case 3:
                return "MEDIA";
            case 4:
                return "NUX";
            case 5:
                return "API";
            case 6:
                return "STATS";
            case 7:
                return "UTILS";
            case 8:
                return "NOTIFS";
            case 9:
                return "DB";
            case 10:
                return "POSTS";
            case 11:
                return "PAGES";
            case 12:
                return "COMMENTS";
            case 13:
                return "THEMES";
            case 14:
                return "TESTS";
            case 15:
                return "PROFILING";
            case 16:
                return "SIMPERIUM";
            case 17:
                return "SUGGESTION";
            case 18:
                return "MAIN";
            case 19:
                return "SETTINGS";
            case 20:
                return "PLANS";
            case 21:
                return "PEOPLE";
            case EventType.WINDOW_STATE /* 22 */:
                return "SHARING";
            case EventType.AUDIO /* 23 */:
                return "PLUGINS";
            case EventType.VIDEO /* 24 */:
                return "ACTIVITY_LOG";
            case EventType.SUBS /* 25 */:
                return "JETPACK_BACKUP";
            case EventType.CDN /* 26 */:
                return "JETPACK_REWIND";
            case 27:
                return "JETPACK_SCAN";
            case 28:
                return "JETPACK_REMOTE_INSTALL";
            case 29:
                return "SUPPORT";
            case 30:
                return "SITE_CREATION";
            case 31:
                return "DOMAIN_REGISTRATION";
            case 32:
                return "FEATURE_ANNOUNCEMENT";
            case 33:
                return "PREPUBLISHING_NUDGES";
            case 34:
                return "MY_SITE_DASHBOARD";
            case 35:
                return "JETPACK_MIGRATION";
            default:
                throw null;
        }
    }
}

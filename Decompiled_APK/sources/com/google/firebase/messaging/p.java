package com.google.firebase.messaging;

import android.app.UiModeManager;
import android.content.res.Resources;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import androidx.appcompat.widget.d1;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3747w;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3755x;
import com.j256.ormlite.dao.Dao;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.I0;
import com.quizlet.data.model.Q;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.setpage.viewmodel.P;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.MissingFormatArgumentException;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class p implements d1, io.reactivex.rxjava3.functions.h, com.quizlet.local.ormlite.database.b, com.quizlet.analytics.marketing.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ p(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static String C(String str) {
        return str.startsWith("gcm.n.") ? str.substring(6) : str;
    }

    public static boolean z(Bundle bundle) {
        return "1".equals(bundle.getString("gcm.n.e")) || "1".equals(bundle.getString("gcm.n.e".replace("gcm.n.", "gcm.notification.")));
    }

    public void A(String str) {
        EventLoggerExt.c((EventLogger) this.b, new com.quizlet.features.notes.logging.c(str, 23));
    }

    public Bundle B() {
        Bundle bundle = (Bundle) this.b;
        Bundle bundle2 = new Bundle(bundle);
        for (String str : bundle.keySet()) {
            if (!str.startsWith("google.c.a.") && !str.equals("from")) {
                bundle2.remove(str);
            }
        }
        return bundle2;
    }

    @Override // com.quizlet.analytics.marketing.b
    public void a(com.quizlet.analytics.marketing.a deepLinkData) {
        Intrinsics.checkNotNullParameter(deepLinkData, "deepLinkData");
        ((com.quizlet.login.intro.viewmodel.e) this.b).l.h(new com.quizlet.login.intro.data.k(deepLinkData.a));
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        C4127f1 c4127f1Q;
        switch (this.a) {
            case 12:
                List folders = (List) obj;
                Intrinsics.checkNotNullParameter(folders, "folders");
                com.quizlet.data.repository.folder.i iVar = (com.quizlet.data.repository.folder.i) this.b;
                return ((com.quizlet.remote.model.folder.p) iVar.a.c).f(folders).e(new com.onetrust.otpublishers.headless.UI.fragment.q((com.quizlet.local.ormlite.models.bookmark.a) iVar.a.b, 9));
            case 14:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                ((org.slf4j.b) ((com.quizlet.data.repository.progress.b) this.b).c).p("Storage error trying to fetch ProgressReset", error.getMessage());
                return io.reactivex.rxjava3.internal.operators.observable.E.a;
            case 15:
                com.quizlet.data.repository.studysetwithcreatorinclass.a remoteData = (com.quizlet.data.repository.studysetwithcreatorinclass.a) obj;
                Intrinsics.checkNotNullParameter(remoteData, "remoteData");
                return ((com.quizlet.data.repository.studysetwithcreatorinclass.g) this.b).m(remoteData);
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.infra.legacysyncengine.features.properties.d studySetProperties = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
                Intrinsics.checkNotNullParameter(studySetProperties, "studySetProperties");
                P p = (P) this.b;
                return p.s.b(p.d, studySetProperties).e(new com.quizlet.data.repository.activitycenter.b(21, p, studySetProperties));
            case EventType.AUDIO /* 23 */:
                ApiResponse p0 = (ApiResponse) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar = (com.quizlet.data.repository.folderwithcreatorinclass.e) this.b;
                eVar.getClass();
                io.reactivex.rxjava3.internal.operators.single.g gVarG = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(6, p0, eVar), 4).e(new com.google.android.material.floatingactionbutton.c(eVar, 24)).g(com.quizlet.infra.legacysyncengine.net.api.a.c);
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            case EventType.SUBS /* 25 */:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) this.b;
                aVar.getClass();
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(it2, 10));
                Iterator it3 = it2.iterator();
                while (it3.hasNext()) {
                    arrayList.add(com.quizlet.local.ormlite.models.folder.a.a((AbstractC4119d0) it3.next()));
                }
                io.reactivex.rxjava3.internal.operators.single.g gVarE = ((ModelIdentityProvider) aVar.b).generateLocalIdsIfNeededAsync(arrayList).e(new com.google.firebase.crashlytics.internal.common.j(aVar, 22));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return gVarE;
            case EventType.CDN /* 26 */:
                I0 it4 = (I0) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                if (it4 instanceof C4116c1) {
                    DBProgressReset dBProgressReset = (DBProgressReset) ((C4116c1) it4).a;
                    Object obj2 = ((com.quizlet.data.repository.folderwithcreator.e) this.b).d;
                    c4127f1Q = com.quizlet.shared.usecase.folderstudymaterials.c.q(dBProgressReset);
                } else {
                    c4127f1Q = null;
                }
                return c4127f1Q == null ? Q.a : new C4116c1(c4127f1Q);
            case 27:
                List studySetWithCreators = (List) obj;
                Intrinsics.checkNotNullParameter(studySetWithCreators, "studySetWithCreators");
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                int iA = U.a(kotlin.collections.C.q(studySetWithCreators, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA);
                for (Object obj3 : studySetWithCreators) {
                    linkedHashMap2.put(Long.valueOf(((StudySetWithCreator) obj3).a.a), obj3);
                }
                for (com.quizlet.data.model.F f : (List) this.b) {
                    StudySetWithCreator studySetWithCreator = (StudySetWithCreator) linkedHashMap2.get(Long.valueOf(f.c));
                    if (studySetWithCreator != null) {
                        long j = f.b;
                        if (linkedHashMap.get(Long.valueOf(j)) == null) {
                            linkedHashMap.put(Long.valueOf(j), new ArrayList());
                        }
                        List list = (List) linkedHashMap.get(Long.valueOf(j));
                        if (list != null) {
                            list.add(new C4117c2(studySetWithCreator.a, studySetWithCreator.b, f.g, f.f, null));
                        }
                    }
                }
                return linkedHashMap;
            default:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                return new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.database.b) this.b).f(modelsWithIds), null, Boolean.TRUE, 0).g(new com.google.android.gms.tasks.n(modelsWithIds, 3));
        }
    }

    @Override // com.quizlet.analytics.marketing.b
    public void b(String errorMessage) {
        Intrinsics.checkNotNullParameter(errorMessage, "errorMessage");
    }

    @Override // androidx.appcompat.widget.d1
    public boolean c(String newSearchQuery) {
        Intrinsics.checkNotNullParameter(newSearchQuery, "newText");
        int length = newSearchQuery.length();
        com.onetrust.otpublishers.headless.UI.fragment.D d = (com.onetrust.otpublishers.headless.UI.fragment.D) this.b;
        if (length == 0) {
            com.google.firebase.perf.logging.b bVar = com.onetrust.otpublishers.headless.UI.fragment.D.D;
            com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = d.X();
            eVarX.getClass();
            Intrinsics.checkNotNullParameter("", "newSearchQuery");
            eVarX.e = "";
            eVarX.D();
            return false;
        }
        com.google.firebase.perf.logging.b bVar2 = com.onetrust.otpublishers.headless.UI.fragment.D.D;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX2 = d.X();
        eVarX2.getClass();
        Intrinsics.checkNotNullParameter(newSearchQuery, "newSearchQuery");
        eVarX2.e = newSearchQuery;
        eVarX2.D();
        return false;
    }

    public JSONObject d(View view) throws JSONException {
        int currentModeType;
        JSONObject jSONObjectA = com.iab.omid.library.amazon.utils.b.a(0, 0, 0, 0);
        UiModeManager uiModeManager = AbstractC3747w.a;
        try {
            jSONObjectA.put("noOutputDevice", com.iab.omid.library.amazon.utils.a.a[AbstractC0147y.k((uiModeManager == null || (currentModeType = uiModeManager.getCurrentModeType()) == 1 || currentModeType != 4) ? 2 : AbstractC3755x.a)] == 1);
            return jSONObjectA;
        } catch (JSONException e) {
            Log.e("OMIDLIB", "Error with setting output device status", e);
            return jSONObjectA;
        }
    }

    @Override // androidx.appcompat.widget.d1
    public boolean e(String newSearchQuery) {
        Intrinsics.checkNotNullParameter(newSearchQuery, "query");
        com.google.firebase.perf.logging.b bVar = com.onetrust.otpublishers.headless.UI.fragment.D.D;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = ((com.onetrust.otpublishers.headless.UI.fragment.D) this.b).X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(newSearchQuery, "newSearchQuery");
        eVarX.e = newSearchQuery;
        eVarX.D();
        return false;
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return com.quizlet.local.ormlite.util.b.a(i(), models);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.util.List r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.repository.folderstudymaterial.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.repository.folderstudymaterial.b r0 = (com.quizlet.data.repository.folderstudymaterial.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folderstudymaterial.b r0 = new com.quizlet.data.repository.folderstudymaterial.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            java.lang.Object r6 = r4.b
            com.quizlet.data.repository.qclass.c r6 = (com.quizlet.data.repository.qclass.c) r6
            java.lang.Object r5 = r6.j(r5, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.g(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean h(String str) {
        String strQ = q(str);
        return "1".equals(strQ) || Boolean.parseBoolean(strQ);
    }

    public Dao i() {
        Object value = ((kotlin.u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Dao) value;
    }

    public Integer j(String str) {
        String strQ = q(str);
        if (TextUtils.isEmpty(strQ)) {
            return null;
        }
        try {
            return Integer.valueOf(Integer.parseInt(strQ));
        } catch (NumberFormatException unused) {
            Log.w("NotificationParams", "Couldn't parse value of " + C(str) + "(" + strQ + ") into an int");
            return null;
        }
    }

    public JSONArray k(String str) {
        String strQ = q(str);
        if (TextUtils.isEmpty(strQ)) {
            return null;
        }
        try {
            return new JSONArray(strQ);
        } catch (JSONException unused) {
            Log.w("NotificationParams", "Malformed JSON for key " + C(str) + ": " + strQ + ", falling back to default");
            return null;
        }
    }

    public int[] l() {
        JSONArray jSONArrayK = k("gcm.n.light_settings");
        if (jSONArrayK == null) {
            return null;
        }
        int[] iArr = new int[3];
        try {
            if (jSONArrayK.length() != 3) {
                throw new JSONException("lightSettings don't have all three fields");
            }
            int color = Color.parseColor(jSONArrayK.optString(0));
            if (color == -16777216) {
                throw new IllegalArgumentException("Transparent color is invalid");
            }
            iArr[0] = color;
            iArr[1] = jSONArrayK.optInt(1);
            iArr[2] = jSONArrayK.optInt(2);
            return iArr;
        } catch (IllegalArgumentException e) {
            Log.w("NotificationParams", "LightSettings is invalid: " + jSONArrayK + ". " + e.getMessage() + ". Skipping setting LightSettings");
            return null;
        } catch (JSONException unused) {
            Log.w("NotificationParams", "LightSettings is invalid: " + jSONArrayK + ". Skipping setting LightSettings");
            return null;
        }
    }

    public Object[] m(String str) {
        JSONArray jSONArrayK = k(str.concat("_loc_args"));
        if (jSONArrayK == null) {
            return null;
        }
        int length = jSONArrayK.length();
        String[] strArr = new String[length];
        for (int i = 0; i < length; i++) {
            strArr[i] = jSONArrayK.optString(i);
        }
        return strArr;
    }

    public String n(String str) {
        return q(str.concat("_loc_key"));
    }

    public Long o() {
        String strQ = q("gcm.n.event_time");
        if (TextUtils.isEmpty(strQ)) {
            return null;
        }
        try {
            return Long.valueOf(Long.parseLong(strQ));
        } catch (NumberFormatException unused) {
            Log.w("NotificationParams", "Couldn't parse value of " + C("gcm.n.event_time") + "(" + strQ + ") into a long");
            return null;
        }
    }

    public String p(Resources resources, String str, String str2) {
        String strQ = q(str2);
        if (!TextUtils.isEmpty(strQ)) {
            return strQ;
        }
        String strN = n(str2);
        if (!TextUtils.isEmpty(strN)) {
            int identifier = resources.getIdentifier(strN, "string", str);
            if (identifier == 0) {
                Log.w("NotificationParams", C(str2.concat("_loc_key")) + " resource not found: " + str2 + " Default value will be used.");
                return null;
            }
            Object[] objArrM = m(str2);
            if (objArrM == null) {
                return resources.getString(identifier);
            }
            try {
                return resources.getString(identifier, objArrM);
            } catch (MissingFormatArgumentException e) {
                Log.w("NotificationParams", "Missing format argument for " + C(str2) + ": " + Arrays.toString(objArrM) + " Default value will be used.", e);
            }
        }
        return null;
    }

    public String q(String str) {
        Bundle bundle = (Bundle) this.b;
        if (!bundle.containsKey(str) && str.startsWith("gcm.n.")) {
            String strReplace = !str.startsWith("gcm.n.") ? str : str.replace("gcm.n.", "gcm.notification.");
            if (bundle.containsKey(strReplace)) {
                str = strReplace;
            }
        }
        return bundle.getString(str);
    }

    public long[] r() {
        JSONArray jSONArrayK = k("gcm.n.vibrate_timings");
        if (jSONArrayK == null) {
            return null;
        }
        try {
            if (jSONArrayK.length() <= 1) {
                throw new JSONException("vibrateTimings have invalid length");
            }
            int length = jSONArrayK.length();
            long[] jArr = new long[length];
            for (int i = 0; i < length; i++) {
                jArr[i] = jSONArrayK.optLong(i);
            }
            return jArr;
        } catch (NumberFormatException | JSONException unused) {
            Log.w("NotificationParams", "User defined vibrateTimings is invalid: " + jSONArrayK + ". Skipping setting vibrateTimings.");
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable s(java.util.ArrayList r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.features.folders.addtofolder.viewmodel.usecase.d
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.d r0 = (com.quizlet.features.folders.addtofolder.viewmodel.usecase.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.d r0 = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.d
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.util.List r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> Lb2
            goto L59
        L29:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r7.b     // Catch: java.lang.Exception -> Lb2
            com.quizlet.data.repository.explanations.myexplanations.a r9 = (com.quizlet.data.repository.explanations.myexplanations.a) r9     // Catch: java.lang.Exception -> Lb2
            java.lang.Integer r2 = new java.lang.Integer     // Catch: java.lang.Exception -> Lb2
            r4 = 50
            r2.<init>(r4)     // Catch: java.lang.Exception -> Lb2
            kotlin.enums.a r4 = com.quizlet.data.model.Y.a()     // Catch: java.lang.Exception -> Lb2
            io.reactivex.rxjava3.internal.operators.single.j r5 = io.reactivex.rxjava3.internal.operators.single.j.a     // Catch: java.lang.Exception -> Lb2
            java.lang.String r6 = "never(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)     // Catch: java.lang.Exception -> Lb2
            io.reactivex.rxjava3.internal.operators.single.g r9 = r9.g(r2, r4, r5)     // Catch: java.lang.Exception -> Lb2
            r0.j = r8     // Catch: java.lang.Exception -> Lb2
            r0.m = r3     // Catch: java.lang.Exception -> Lb2
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r9, r0)     // Catch: java.lang.Exception -> Lb2
            if (r9 != r1) goto L59
            return r1
        L59:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r0)     // Catch: java.lang.Exception -> Lb2
            java.util.List r9 = (java.util.List) r9     // Catch: java.lang.Exception -> Lb2
            java.util.ArrayList r0 = new java.util.ArrayList     // Catch: java.lang.Exception -> Lb2
            r1 = 10
            int r1 = kotlin.collections.C.q(r9, r1)     // Catch: java.lang.Exception -> Lb2
            r0.<init>(r1)     // Catch: java.lang.Exception -> Lb2
            java.util.Iterator r9 = r9.iterator()     // Catch: java.lang.Exception -> Lb2
        L6f:
            boolean r1 = r9.hasNext()     // Catch: java.lang.Exception -> Lb2
            if (r1 == 0) goto Lb1
            java.lang.Object r1 = r9.next()     // Catch: java.lang.Exception -> Lb2
            com.quizlet.data.model.B0 r1 = (com.quizlet.data.model.B0) r1     // Catch: java.lang.Exception -> Lb2
            com.quizlet.ui.models.content.listitem.o r1 = com.google.android.gms.internal.mlkit_vision_barcode.G0.c(r1)     // Catch: java.lang.Exception -> Lb2
            r2 = 0
            if (r8 == 0) goto L89
            boolean r4 = r8.isEmpty()     // Catch: java.lang.Exception -> Lb2
            if (r4 == 0) goto L89
            goto La8
        L89:
            java.util.Iterator r4 = r8.iterator()     // Catch: java.lang.Exception -> Lb2
        L8d:
            boolean r5 = r4.hasNext()     // Catch: java.lang.Exception -> Lb2
            if (r5 == 0) goto La8
            java.lang.Object r5 = r4.next()     // Catch: java.lang.Exception -> Lb2
            com.quizlet.ui.models.content.listitem.o r5 = (com.quizlet.ui.models.content.listitem.o) r5     // Catch: java.lang.Exception -> Lb2
            java.lang.String r5 = r5.d()     // Catch: java.lang.Exception -> Lb2
            java.lang.String r6 = r1.d()     // Catch: java.lang.Exception -> Lb2
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)     // Catch: java.lang.Exception -> Lb2
            if (r5 == 0) goto L8d
            r2 = r3
        La8:
            com.quizlet.features.folders.addtofolder.data.s r4 = new com.quizlet.features.folders.addtofolder.data.s     // Catch: java.lang.Exception -> Lb2
            r4.<init>(r1, r2)     // Catch: java.lang.Exception -> Lb2
            r0.add(r4)     // Catch: java.lang.Exception -> Lb2
            goto L6f
        Lb1:
            return r0
        Lb2:
            kotlin.collections.K r8 = kotlin.collections.K.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.s(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object t(com.quizlet.data.model.R1 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.notes.g
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.notes.g r0 = (com.quizlet.data.interactor.notes.g) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.notes.g r0 = new com.quizlet.data.interactor.notes.g
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.model.R1 r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L50
            goto L49
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L50
            com.quizlet.shared.usecase.studynotes.r r6 = (com.quizlet.shared.usecase.studynotes.r) r6     // Catch: java.lang.Exception -> L50
            java.lang.String r2 = r5.b()     // Catch: java.lang.Exception -> L50
            r0.j = r5     // Catch: java.lang.Exception -> L50
            r0.m = r3     // Catch: java.lang.Exception -> L50
            com.quizlet.shared.usecase.studynotes.h r6 = (com.quizlet.shared.usecase.studynotes.h) r6     // Catch: java.lang.Exception -> L50
            java.lang.Object r6 = r6.a(r2, r0)     // Catch: java.lang.Exception -> L50
            if (r6 != r1) goto L49
            return r1
        L49:
            com.quizlet.shared.models.notes.b r6 = (com.quizlet.shared.models.notes.b) r6     // Catch: java.lang.Exception -> L50
            com.quizlet.data.model.R1 r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.D6.n(r6)     // Catch: java.lang.Exception -> L50
            return r5
        L50:
            com.quizlet.data.model.w r6 = com.quizlet.data.model.EnumC4175w.ERROR
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "artifactStatus"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            boolean r0 = r5 instanceof com.quizlet.data.model.EssayInfo
            java.lang.String r1 = "status"
            java.lang.String r2 = "uuid"
            if (r0 == 0) goto L76
            com.quizlet.data.model.EssayInfo r5 = (com.quizlet.data.model.EssayInfo) r5
            java.lang.String r0 = r5.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            com.quizlet.data.model.EssayInfo r1 = new com.quizlet.data.model.EssayInfo
            java.util.List r5 = r5.c
            r1.<init>(r0, r6, r5)
            goto Lcf
        L76:
            boolean r0 = r5 instanceof com.quizlet.data.model.FlashcardsInfo
            if (r0 == 0) goto L8e
            com.quizlet.data.model.FlashcardsInfo r5 = (com.quizlet.data.model.FlashcardsInfo) r5
            java.lang.String r0 = r5.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            com.quizlet.data.model.FlashcardsInfo r1 = new com.quizlet.data.model.FlashcardsInfo
            java.lang.Long r2 = r5.c
            java.util.List r5 = r5.d
            r1.<init>(r0, r6, r2, r5)
            goto Lcf
        L8e:
            boolean r0 = r5 instanceof com.quizlet.data.model.TitleInfo
            if (r0 == 0) goto La4
            com.quizlet.data.model.TitleInfo r5 = (com.quizlet.data.model.TitleInfo) r5
            java.lang.String r0 = r5.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            com.quizlet.data.model.TitleInfo r1 = new com.quizlet.data.model.TitleInfo
            java.lang.String r5 = r5.c
            r1.<init>(r0, r6, r5)
            goto Lcf
        La4:
            boolean r0 = r5 instanceof com.quizlet.data.model.OutlineMarkdownInfo
            if (r0 == 0) goto Lba
            com.quizlet.data.model.OutlineMarkdownInfo r5 = (com.quizlet.data.model.OutlineMarkdownInfo) r5
            java.lang.String r0 = r5.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            com.quizlet.data.model.OutlineMarkdownInfo r1 = new com.quizlet.data.model.OutlineMarkdownInfo
            java.lang.String r5 = r5.c
            r1.<init>(r0, r6, r5)
            goto Lcf
        Lba:
            boolean r0 = r5 instanceof com.quizlet.data.model.ReviewSheetInfo
            if (r0 == 0) goto Ld0
            com.quizlet.data.model.ReviewSheetInfo r5 = (com.quizlet.data.model.ReviewSheetInfo) r5
            java.lang.String r0 = r5.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            com.quizlet.data.model.ReviewSheetInfo r1 = new com.quizlet.data.model.ReviewSheetInfo
            java.lang.String r5 = r5.c
            r1.<init>(r0, r6, r5)
        Lcf:
            return r1
        Ld0:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.t(com.quizlet.data.model.R1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r5v3, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object u(java.lang.String r5, int r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.course.h
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.course.h r0 = (com.quizlet.data.interactor.course.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.course.h r0 = new com.quizlet.data.interactor.course.h
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L49
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            androidx.work.impl.model.n r7 = (androidx.work.impl.model.n) r7
            com.quizlet.remote.model.course.i r2 = new com.quizlet.remote.model.course.i
            r3 = 0
            r2.<init>(r7, r5, r6, r3)
            java.lang.Object r5 = r7.d
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r2, r0)
            if (r7 != r1) goto L49
            return r1
        L49:
            com.quizlet.data.model.L r7 = (com.quizlet.data.model.L) r7
            java.lang.Object r5 = r7.a
            boolean r5 = r5.isEmpty()
            if (r5 != 0) goto L54
            return r7
        L54:
            com.quizlet.data.repository.course.exceptions.CourseNotFoundException r5 = new com.quizlet.data.repository.course.exceptions.CourseNotFoundException
            r5.<init>()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.u(java.lang.String, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object v(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.search.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.search.a r0 = (com.quizlet.data.interactor.search.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.search.a r0 = new com.quizlet.data.interactor.search.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.lang.String r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L50
            goto L4d
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L50
            com.quizlet.remote.model.search.d r6 = (com.quizlet.remote.model.search.d) r6     // Catch: java.lang.Exception -> L50
            r0.j = r5     // Catch: java.lang.Exception -> L50
            r0.m = r3     // Catch: java.lang.Exception -> L50
            com.quizlet.remote.model.search.c r2 = new com.quizlet.remote.model.search.c     // Catch: java.lang.Exception -> L50
            r3 = 0
            r2.<init>(r6, r5, r3)     // Catch: java.lang.Exception -> L50
            java.lang.Object r6 = r6.b     // Catch: java.lang.Exception -> L50
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6     // Catch: java.lang.Exception -> L50
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r2, r0)     // Catch: java.lang.Exception -> L50
            if (r6 != r1) goto L4d
            return r1
        L4d:
            com.quizlet.data.model.search.a r6 = (com.quizlet.data.model.search.a) r6     // Catch: java.lang.Exception -> L50
            return r6
        L50:
            com.quizlet.data.model.search.a r6 = new com.quizlet.data.model.search.a
            r6.<init>(r5)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.v(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object w(java.lang.String r5, com.quizlet.generated.enums.y1 r6, java.lang.Long r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.foldertoadd.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.foldertoadd.a r0 = (com.quizlet.data.interactor.foldertoadd.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.foldertoadd.a r0 = new com.quizlet.data.interactor.foldertoadd.a
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r5 = r8.a
            goto L43
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.l = r3
            java.lang.Object r8 = r4.b
            com.google.firebase.crashlytics.internal.common.j r8 = (com.google.firebase.crashlytics.internal.common.j) r8
            java.lang.Object r5 = r8.c(r5, r6, r7, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L5d
            java.util.List r5 = (java.util.List) r5     // Catch: java.lang.Throwable -> L56
            com.google.zxing.aztec.encoder.c r6 = new com.google.zxing.aztec.encoder.c     // Catch: java.lang.Throwable -> L56
            r7 = 7
            r6.<init>(r7)     // Catch: java.lang.Throwable -> L56
            java.util.List r5 = kotlin.collections.CollectionsKt.n0(r5, r6)     // Catch: java.lang.Throwable -> L56
            return r5
        L56:
            r5 = move-exception
            kotlin.p r6 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
        L5d:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.w(java.lang.String, com.quizlet.generated.enums.y1, java.lang.Long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.lang.Iterable, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable x(java.lang.String r12, kotlin.coroutines.jvm.internal.c r13) throws java.lang.Throwable {
        /*
            r11 = this;
            boolean r0 = r13 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.j
            if (r0 == 0) goto L13
            r0 = r13
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.j r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.j r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.j
            r0.<init>(r11, r13)
        L18:
            java.lang.Object r13 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            java.lang.String r12 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            goto L52
        L29:
            r0 = move-exception
            r12 = r0
            goto L9a
        L2d:
            r3 = r12
            goto La1
        L30:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            int r13 = r12.length()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            if (r13 == 0) goto L94
            java.lang.Object r13 = r11.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            com.google.firebase.messaging.p r13 = (com.google.firebase.messaging.p) r13     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r0.j = r12     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r0.m = r3     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r2 = 20
            java.lang.Object r13 = r13.u(r12, r2, r0)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            if (r13 != r1) goto L52
            return r1
        L52:
            com.quizlet.data.model.L r13 = (com.quizlet.data.model.L) r13     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            java.lang.Object r0 = r13.a     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            java.util.ArrayList r1 = new java.util.ArrayList     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r2 = 10
            int r2 = kotlin.collections.C.q(r0, r2)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r1.<init>(r2)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            java.util.Iterator r0 = r0.iterator()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
        L65:
            boolean r2 = r0.hasNext()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            if (r2 == 0) goto L91
            java.lang.Object r2 = r0.next()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            com.quizlet.data.model.Course r2 = (com.quizlet.data.model.Course) r2     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            long r4 = r2.a     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            java.lang.String r3 = r2.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            java.lang.String r7 = r2.e
            if (r3 == 0) goto L82
            int r2 = r3.length()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            if (r2 != 0) goto L80
            r3 = r7
        L80:
            r6 = r3
            goto L83
        L82:
            r6 = r7
        L83:
            java.lang.String r9 = r13.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r8 = 0
            r10 = 24
            r3.<init>(r4, r6, r7, r8, r9, r10)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r1.add(r3)     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            goto L65
        L91:
            kotlin.p r12 = kotlin.r.b     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            return r1
        L94:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException r13 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            r13.<init>()     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
            throw r13     // Catch: java.lang.Exception -> L29 com.quizlet.data.repository.course.exceptions.CourseNotFoundException -> L2d
        L9a:
            kotlin.p r13 = kotlin.r.b
            kotlin.q r12 = androidx.glance.appwidget.protobuf.Z.b(r12)
            goto Lba
        La1:
            kotlin.p r12 = kotlin.r.b
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoCourseException r12 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoCourseException
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b r5 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b.a
            java.lang.String r4 = ""
            r6 = 0
            r1 = -1
            r7 = 48
            r0.<init>(r1, r3, r4, r5, r6, r7)
            r12.<init>(r0)
            kotlin.q r12 = androidx.glance.appwidget.protobuf.Z.b(r12)
        Lba:
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.p.x(java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public io.reactivex.rxjava3.core.p y(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarQ = userProps.q();
        ((com.quizlet.shared.usecase.folderstudymaterials.c) this.b).getClass();
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(Boolean.valueOf(Build.VERSION.SDK_INT >= 31));
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF2 = io.reactivex.rxjava3.core.p.f(Boolean.TRUE);
        Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
        return com.google.android.gms.dynamite.d.b(gVarQ, com.google.android.gms.dynamite.d.b(bVarF, bVarF2));
    }

    public p(com.quizlet.remote.model.search.d repository) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public p(C3 practiceTestsRepository) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    public p(p searchCoursesUseCase) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(searchCoursesUseCase, "searchCoursesUseCase");
        this.b = searchCoursesUseCase;
    }

    public p(com.quizlet.shared.usecase.studynotes.r getStudyNotesArtifactInfoUseCase) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(getStudyNotesArtifactInfoUseCase, "getStudyNotesArtifactInfoUseCase");
        this.b = getStudyNotesArtifactInfoUseCase;
    }

    public p(androidx.work.impl.model.n repository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public p(com.quizlet.data.repository.user.eligibility.g userFeatureEligibilityRepository) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(userFeatureEligibilityRepository, "userFeatureEligibilityRepository");
        this.b = userFeatureEligibilityRepository;
    }

    public p(com.quizlet.remote.model.set.d recommendedSetRemoteDataStore) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(recommendedSetRemoteDataStore, "recommendedSetRemoteDataStore");
        this.b = recommendedSetRemoteDataStore;
    }

    public p(com.quizlet.data.repository.qclass.c dataStore) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public p(com.quizlet.data.repository.achievements.h repository) {
        this.a = 5;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = repository;
    }

    public p(com.google.firebase.crashlytics.internal.common.j getFoldersToAddMaterialRepository) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(getFoldersToAddMaterialRepository, "getFoldersToAddMaterialRepository");
        this.b = getFoldersToAddMaterialRepository;
    }

    public p(com.quizlet.data.repository.explanations.myexplanations.a getMyExplanationsUseCase) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(getMyExplanationsUseCase, "getMyExplanationsUseCase");
        this.b = getMyExplanationsUseCase;
    }

    public p(DatabaseHelper database) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 8));
    }

    public p(com.facebook.z setInSelectedTermsModeCache) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeCache, "setInSelectedTermsModeCache");
        this.b = setInSelectedTermsModeCache;
    }

    public p(Bundle bundle) {
        this.a = 0;
        if (bundle != null) {
            this.b = new Bundle(bundle);
            return;
        }
        throw new NullPointerException("data");
    }

    public p(EventLogger eventLogger) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = eventLogger;
    }
}

package androidx.work.impl.model;

import android.content.Context;
import android.graphics.Matrix;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemClock;
import android.text.Spannable;
import android.text.SpannableString;
import android.util.Log;
import android.view.Surface;
import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.V;
import androidx.camera.core.C0157i;
import androidx.collection.C0208f;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.foundation.lazy.layout.M;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.g0;
import androidx.compose.ui.layout.h0;
import androidx.compose.ui.platform.InterfaceC0945h0;
import androidx.compose.ui.platform.N;
import androidx.emoji2.text.B;
import androidx.emoji2.text.y;
import androidx.emoji2.text.z;
import androidx.lifecycle.m0;
import androidx.work.impl.WorkDatabase_Impl;
import com.android.volley.AuthFailureError;
import com.android.volley.ClientError;
import com.android.volley.NetworkError;
import com.android.volley.NoConnectionError;
import com.android.volley.ServerError;
import com.android.volley.TimeoutError;
import com.android.volley.VolleyError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.measurement.P;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3562y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.measurement.internal.AppMeasurementDynamiteService;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.data.model.StudySet;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.util.QLocalizedException;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.AbstractC5040y;
import okhttp3.H;
import okhttp3.J;
import okio.InterfaceC5093j;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class l implements androidx.camera.core.impl.utils.futures.c, h0, InterfaceC0945h0, androidx.emoji2.text.p, com.android.volley.f, InterfaceC3885o0, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ l(int i) {
        this.a = i;
    }

    public static ArrayList f(JSONArray jSONArray) throws JSONException {
        JSONArray jSONArray2 = new JSONArray();
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                h(i, jSONArray, jSONArray2, new JSONObject());
            } catch (JSONException e) {
                Z.p("Error on parsing Categories list. Error msg = ", e, "OTSDKListFilter", 6);
            }
        }
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
            try {
                JSONObject jSONObject = jSONArray2.getJSONObject(i2);
                if (jSONObject.has("CustomGroupId")) {
                    arrayList.add(jSONObject.getString("CustomGroupId"));
                }
            } catch (JSONException e2) {
                Z.p("Error on parsing Categories list to get category string list. Error msg = ", e2, "OTSDKListFilter", 6);
            }
        }
        return arrayList;
    }

    public static void h(int i, JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = jSONArray.getJSONObject(i);
        if (!jSONObject2.has("ShowSDKListLink") || jSONObject2.getBoolean("ShowSDKListLink")) {
            if ((jSONObject2.getString("Type").equals("COOKIE") && jSONObject2.getJSONArray("FirstPartyCookies").length() > 0) || !jSONObject2.optBoolean("ShowSubgroup", false)) {
                String strOptString = jSONObject2.optString("GroupNameMobile");
                if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                    strOptString = jSONObject2.optString("GroupName");
                }
                jSONObject.put("GroupName", strOptString);
                jSONObject.put("CustomGroupId", jSONObject2.getString("CustomGroupId"));
                jSONArray2.put(jSONObject);
            }
            if (jSONObject2.has("SubGroups") && jSONObject2.optBoolean("ShowSubgroup", false)) {
                JSONArray jSONArray3 = jSONObject2.getJSONArray("SubGroups");
                for (int i2 = 0; i2 < jSONArray3.length(); i2++) {
                    JSONObject jSONObject3 = new JSONObject();
                    if (jSONArray3.getJSONObject(i2).getString("Type").equals("COOKIE") && jSONArray3.getJSONObject(i2).getJSONArray("FirstPartyCookies").length() > 0) {
                        JSONObject jSONObject4 = jSONArray3.getJSONObject(i2);
                        String strOptString2 = jSONObject4.optString("GroupNameMobile");
                        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                            strOptString2 = jSONObject4.optString("GroupName");
                        }
                        jSONObject3.put("GroupName", strOptString2);
                        jSONObject3.put("CustomGroupId", jSONArray3.getJSONObject(i2).getString("CustomGroupId"));
                        jSONArray2.put(jSONObject3);
                    }
                }
            }
        }
    }

    private final void o(Throwable th) {
    }

    @Override // androidx.emoji2.text.p
    public Object a() {
        return (B) this.b;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) throws IOException {
        Map map;
        int i;
        io.reactivex.rxjava3.internal.operators.maybe.e eVar;
        InterfaceC5093j interfaceC5093jF0;
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                List list = (List) this.b;
                Intrinsics.d(list);
                return AbstractC3771z.c((com.google.mlkit.common.sdkinternal.b) ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c, list);
            case EventType.AUDIO /* 23 */:
                Map serverIdToLocalIdMap = (Map) obj;
                Intrinsics.checkNotNullParameter(serverIdToLocalIdMap, "serverIdToLocalIdMap");
                ((com.quizlet.local.ormlite.models.bookmark.a) this.b).getClass();
                List<StudySet> list2 = (List) this.c;
                ArrayList arrayList = new ArrayList(C.q(list2, 10));
                for (StudySet studySet : list2) {
                    Long l = (Long) serverIdToLocalIdMap.get(Long.valueOf(studySet.a));
                    if (l != null) {
                        long jLongValue = l.longValue();
                        String wordLang = studySet.f;
                        Intrinsics.checkNotNullParameter(wordLang, "wordLang");
                        String defLang = studySet.g;
                        Intrinsics.checkNotNullParameter(defLang, "defLang");
                        String title = studySet.h;
                        Intrinsics.checkNotNullParameter(title, "title");
                        String description = studySet.m;
                        Intrinsics.checkNotNullParameter(description, "description");
                        String webUrl = studySet.t;
                        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
                        map = serverIdToLocalIdMap;
                        studySet = new StudySet(studySet.a, studySet.b, studySet.c, studySet.d, studySet.e, wordLang, defLang, title, studySet.i, studySet.j, studySet.k, studySet.l, description, studySet.n, studySet.o, studySet.p, studySet.q, studySet.r, studySet.s, webUrl, studySet.u, studySet.v, studySet.w, jLongValue, studySet.y, studySet.z, studySet.A, studySet.B, studySet.C);
                    } else {
                        map = serverIdToLocalIdMap;
                    }
                    arrayList.add(studySet);
                    serverIdToLocalIdMap = map;
                }
                return arrayList;
            case EventType.VIDEO /* 24 */:
                Long userId = (Long) obj;
                Intrinsics.checkNotNullParameter(userId, "userId");
                com.google.android.datatransport.cct.internal.s sVar = ((com.quizlet.offline.managers.i) this.b).f;
                long jLongValue2 = userId.longValue();
                com.quizlet.qutils.data.offline.d payload = (com.quizlet.qutils.data.offline.d) this.c;
                Intrinsics.checkNotNullParameter(payload, "payload");
                return sVar.k(payload, jLongValue2, true);
            case EventType.SUBS /* 25 */:
                List list3 = (List) obj;
                Intrinsics.checkNotNullParameter(list3, "list");
                int size = list3.size();
                com.quizlet.quizletandroid.data.management.a aVar = (com.quizlet.quizletandroid.data.management.a) this.b;
                if (size == aVar.a.getNumTerms()) {
                    return io.reactivex.rxjava3.core.p.f(list3);
                }
                com.google.android.datatransport.cct.internal.s sVar2 = (com.google.android.datatransport.cct.internal.s) this.c;
                sVar2.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
                bVar.b(Long.valueOf(aVar.a.getId()), DBTermFields.SET);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                return sVar2.o(aVarA);
            default:
                H response = (H) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                if (response.d()) {
                    try {
                        J j = response.g;
                        if (j == null || (interfaceC5093jF0 = j.f0()) == null) {
                            eVar = new io.reactivex.rxjava3.internal.operators.maybe.e(new IOException("Network had no response body!"), 2);
                        } else {
                            File file = (File) this.c;
                            try {
                                com.facebook.appevents.g.j(interfaceC5093jF0, file);
                                io.reactivex.rxjava3.internal.operators.maybe.l lVarC = io.reactivex.rxjava3.core.g.c(file);
                                interfaceC5093jF0.close();
                                return lVarC;
                            } finally {
                            }
                        }
                    } catch (IOException e) {
                        timber.log.c.a.e(e);
                        ((com.quizlet.data.interactor.course.a) this.b).getClass();
                        String message = e.getMessage();
                        if (message == null || !StringsKt.G(message, "EROFS", false)) {
                            String message2 = e.getMessage();
                            i = (message2 == null || !StringsKt.G(message2, "ENOSPC", false)) ? R.string.failed_to_save_file : R.string.failed_to_save_out_of_storage;
                        } else {
                            i = R.string.failed_to_save_filesystem_error;
                        }
                        return new io.reactivex.rxjava3.internal.operators.maybe.e(new QLocalizedException(i, e), 2);
                    }
                } else {
                    timber.log.c.a.d("File download failed (%d): %s", Integer.valueOf(response.d), response.a.a);
                    eVar = new io.reactivex.rxjava3.internal.operators.maybe.e(new IOException("Download response was unsuccessful"), 2);
                }
                return eVar;
        }
    }

    @Override // androidx.compose.ui.layout.h0
    public void b(g0 g0Var) {
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.c;
        linkedHashMap.clear();
        Iterator it2 = g0Var.a.iterator();
        while (it2.hasNext()) {
            Object objB = ((M) this.b).b(it2.next());
            Integer num = (Integer) linkedHashMap.get(objB);
            int iIntValue = num != null ? num.intValue() : 0;
            if (iIntValue == 7) {
                it2.remove();
            } else {
                linkedHashMap.put(objB, Integer.valueOf(iIntValue + 1));
            }
        }
    }

    @Override // androidx.compose.ui.layout.h0
    public boolean c(Object obj, Object obj2) {
        M m = (M) this.b;
        return Intrinsics.b(m.b(obj), m.b(obj2));
    }

    @Override // androidx.emoji2.text.p
    public boolean d(CharSequence charSequence, int i, int i2, y yVar) {
        if ((yVar.c & 4) > 0) {
            return true;
        }
        if (((B) this.b) == null) {
            this.b = new B(charSequence instanceof Spannable ? (Spannable) charSequence : new SpannableString(charSequence));
        }
        ((com.quizlet.shared.usecase.folderstudymaterials.d) this.c).getClass();
        ((B) this.b).setSpan(new z(yVar), i, i2, 33);
        return true;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0945h0
    public void e(View view, float[] fArr) {
        androidx.compose.ui.graphics.J.d(fArr);
        s(view, fArr);
    }

    public void g(int i, Context context, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        try {
            this.c = oTPublishersHeadlessSDK.getPreferenceCenterData();
            Yh yhD = new com.onetrust.otpublishers.headless.UI.UIProperty.f(context).d(i);
            this.b = yhD;
            String str = (String) yhD.b;
            String strOptString = ((JSONObject) this.c).optString("PcBackgroundColor");
            String str2 = "#FFFFFF";
            if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
                str = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString) ? strOptString : i == 11 ? "#2F2F2F" : "#FFFFFF";
            }
            yhD.b = str;
            Yh yh = (Yh) this.b;
            String str3 = (String) yh.k;
            String strOptString2 = ((JSONObject) this.c).optString("PcButtonColor");
            if (com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                str3 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) ? strOptString2 : i == 11 ? "#80BE5A" : "#6CC04A";
            }
            yh.k = str3;
            androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) ((Yh) this.b).m;
            String str4 = (String) mVar.b;
            String strOptString3 = ((JSONObject) this.c).optString("PcTextColor");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                str2 = str4;
            } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                str2 = strOptString3;
            } else if (i != 11) {
                str2 = "#696969";
            }
            mVar.b = str2;
            androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) ((Yh) this.b).n;
            nVar.j = ((JSONObject) this.c).optString("PCenterApplyFiltersText");
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.f)) {
                nVar.f = ((JSONObject) this.c).optString("PcButtonTextColor");
            }
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.e)) {
                nVar.e = ((JSONObject) this.c).optString("PcButtonColor");
            }
            androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) ((Yh) this.b).l;
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.g)) {
                mVar2.g = ((JSONObject) this.c).optString("PCenterCancelFiltersText");
            }
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar2.b)) {
                mVar2.b = ((JSONObject) this.c).optString("PcTextColor");
            }
            androidx.navigation.internal.m mVar3 = (androidx.navigation.internal.m) ((Yh) this.b).m;
            if (com.onetrust.otpublishers.headless.Internal.a.j((String) mVar3.b)) {
                mVar3.b = ((JSONObject) this.c).optString("PcTextColor");
            }
        } catch (JSONException e) {
            W.a("failed to initialize SDK list filter data, e: ", e, "OTSDKListFilter", 6);
        }
    }

    public Object i(kotlin.coroutines.h hVar) {
        return I1.b(r(), hVar);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3885o0
    public void interceptEvent(String str, String str2, Bundle bundle, long j) {
        try {
            ((P) this.b).H3(str, str2, bundle, j);
        } catch (RemoteException e) {
            Y y = ((AppMeasurementDynamiteService) this.c).a;
            if (y != null) {
                I i = y.i;
                Y.k(i);
                i.j.g("Event interceptor threw exception", e);
            }
        }
    }

    public com.google.firebase.remoteconfig.interop.rollouts.d j(com.google.firebase.remoteconfig.internal.c cVar) {
        String string;
        JSONArray jSONArray = cVar.g;
        long j = cVar.f;
        HashSet hashSet = new HashSet();
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                JSONObject jSONObject = jSONArray.getJSONObject(i);
                String string2 = jSONObject.getString("rolloutId");
                JSONArray jSONArray2 = jSONObject.getJSONArray("affectedParameterKeys");
                if (jSONArray2.length() > 1) {
                    Log.w("FirebaseRemoteConfig", String.format("Rollout has multiple affected parameter keys.Only the first key will be included in RolloutsState. rolloutId: %s, affectedParameterKeys: %s", string2, jSONArray2));
                }
                String strOptString = jSONArray2.optString(0, "");
                com.google.firebase.remoteconfig.internal.c cVarC = ((com.google.firebase.remoteconfig.internal.b) this.b).c();
                String string3 = null;
                if (cVarC == null) {
                    string = null;
                } else {
                    try {
                        string = cVarC.b.getString(strOptString);
                    } catch (JSONException unused) {
                    }
                }
                if (string == null) {
                    com.google.firebase.remoteconfig.internal.c cVarC2 = ((com.google.firebase.remoteconfig.internal.b) this.c).c();
                    if (cVarC2 != null) {
                        try {
                            string3 = cVarC2.b.getString(strOptString);
                        } catch (JSONException unused2) {
                        }
                    }
                    string = string3 != null ? string3 : "";
                }
                int i2 = com.google.firebase.remoteconfig.interop.rollouts.e.a;
                com.google.firebase.remoteconfig.interop.rollouts.b bVar = new com.google.firebase.remoteconfig.interop.rollouts.b();
                if (string2 == null) {
                    throw new NullPointerException("Null rolloutId");
                }
                bVar.a = string2;
                String string4 = jSONObject.getString("variantId");
                if (string4 == null) {
                    throw new NullPointerException("Null variantId");
                }
                bVar.b = string4;
                if (strOptString == null) {
                    throw new NullPointerException("Null parameterKey");
                }
                bVar.c = strOptString;
                bVar.d = string;
                bVar.e = j;
                bVar.f = (byte) (bVar.f | 1);
                hashSet.add(bVar.a());
            } catch (JSONException e) {
                throw new FirebaseRemoteConfigClientException("Exception parsing rollouts metadata to create RolloutsState.", e);
            }
        }
        return new com.google.firebase.remoteconfig.interop.rollouts.d(hashSet);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(com.quizlet.studiablemodels.grading.WrittenResponse r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.features.questiontypes.grading.b
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.questiontypes.grading.b r0 = (com.quizlet.features.questiontypes.grading.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.questiontypes.grading.b r0 = new com.quizlet.features.questiontypes.grading.b
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.studiablemodels.grading.WrittenResponse r11 = r0.k
            androidx.work.impl.model.l r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L48
        L2b:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r0.j = r10
            r0.k = r11
            r0.n = r3
            java.lang.Object r12 = r10.c
            com.quizlet.studiablemodels.grading.d r12 = (com.quizlet.studiablemodels.grading.d) r12
            java.lang.Object r12 = r12.a(r11, r0)
            if (r12 != r1) goto L47
            return r1
        L47:
            r0 = r10
        L48:
            com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer r12 = (com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer) r12
            com.quizlet.studiablemodels.grading.PGradedAnswerMetadata r1 = r12.f
            boolean r2 = r1 instanceof com.quizlet.studiablemodels.grading.PSmartGradedAnswerMetadata
            if (r2 == 0) goto L87
            java.lang.Object r2 = r0.b
            com.quizlet.features.questiontypes.grading.a r2 = (com.quizlet.features.questiontypes.grading.a) r2
            com.quizlet.studiablemodels.grading.PSmartGradedAnswerMetadata r1 = (com.quizlet.studiablemodels.grading.PSmartGradedAnswerMetadata) r1
            long r3 = r1.d
            r2.c(r3)
            java.lang.Object r0 = r0.b
            r2 = r0
            com.quizlet.features.questiontypes.grading.a r2 = (com.quizlet.features.questiontypes.grading.a) r2
            long r8 = r1.e
            com.quizlet.studiablemodels.grading.PLongtextGradingResult r3 = r1.b
            if (r3 == 0) goto L82
            com.quizlet.studiablemodels.grading.StudiableQuestionFeedback r0 = r12.b
            com.quizlet.studiablemodels.grading.StudiableQuestionResponse r0 = r0.b
            java.lang.String r4 = "null cannot be cast to non-null type com.quizlet.studiablemodels.grading.WrittenResponse"
            kotlin.jvm.internal.Intrinsics.e(r0, r4)
            com.quizlet.studiablemodels.grading.WrittenResponse r0 = (com.quizlet.studiablemodels.grading.WrittenResponse) r0
            java.lang.String r5 = r11.a
            java.lang.Long r11 = r1.f
            if (r11 == 0) goto L7c
            long r6 = r11.longValue()
            goto L7d
        L7c:
            r6 = r8
        L7d:
            java.lang.String r4 = r0.a
            r2.a(r3, r4, r5, r6)
        L82:
            boolean r11 = r1.c
            r2.b(r8, r11)
        L87:
            com.quizlet.studiablemodels.grading.b r11 = new com.quizlet.studiablemodels.grading.b
            boolean r0 = r12.e
            com.quizlet.studiablemodels.grading.PGradedAnswerMetadata r1 = r12.f
            r11.<init>(r12, r0, r1)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.l.k(com.quizlet.studiablemodels.grading.WrittenResponse, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x004a  */
    /* JADX WARN: Type inference failed for: r5v1, types: [com.quizlet.quizletandroid.ui.live.f, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v12, types: [com.quizlet.quizletandroid.ui.live.f, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v6, types: [com.quizlet.quizletandroid.ui.live.f, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void l(int r5, java.lang.String r6) {
        /*
            r4 = this;
            r0 = 1000(0x3e8, float:1.401E-42)
            java.lang.String r1 = "view"
            r2 = 0
            if (r5 != r0) goto L13
            java.lang.Object r5 = r4.c
            if (r5 == 0) goto Lf
            r5.A()
            return
        Lf:
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r2
        L13:
            com.quizlet.live.a r0 = com.quizlet.live.a.a
            r0 = 1
            if (r5 != r0) goto L61
            kotlin.jvm.internal.Intrinsics.d(r6)
            java.lang.String r5 = "rawUrl"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r5)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r5)
            java.lang.String r5 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r5)
            androidx.recyclerview.widget.j r5 = new androidx.recyclerview.widget.j
            r5.<init>()
            r5.l(r2, r6)
            okhttp3.s r5 = r5.d()
            java.util.ArrayList r5 = r5.f
            int r6 = r5.size()
            r3 = 2
            if (r6 < r3) goto L4a
            java.lang.Object r5 = r5.get(r0)
            java.lang.String r5 = (java.lang.String) r5
            int r6 = r5.length()
            if (r6 <= 0) goto L4a
            goto L4b
        L4a:
            r5 = r2
        L4b:
            if (r5 == 0) goto L59
            java.lang.Object r6 = r4.c
            if (r6 == 0) goto L55
            r6.s(r5)
            return
        L55:
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r2
        L59:
            java.lang.IllegalArgumentException r5 = new java.lang.IllegalArgumentException
            java.lang.String r6 = "URL is not valid"
            r5.<init>(r6)
            throw r5
        L61:
            r6 = -3
            if (r5 == r6) goto L76
            r6 = -1
            if (r5 == r6) goto L6a
            r6 = -2
            if (r5 != r6) goto L76
        L6a:
            java.lang.Object r5 = r4.c
            if (r5 == 0) goto L72
            r5.w()
            return
        L72:
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r2
        L76:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.l.l(int, java.lang.String):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(com.quizlet.data.model.m2 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.universaluploadflow.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.universaluploadflow.f r0 = (com.quizlet.data.interactor.universaluploadflow.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.universaluploadflow.f r0 = new com.quizlet.data.interactor.universaluploadflow.f
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L28
            goto L6f
        L28:
            r6 = move-exception
            goto L74
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r5.c
            com.quizlet.db.data.caches.UserInfoCache r7 = (com.quizlet.db.data.caches.UserInfoCache) r7
            boolean r7 = r7.b()
            if (r7 != 0) goto L40
            return r3
        L40:
            int[] r7 = com.quizlet.data.interactor.universaluploadflow.e.a
            int r6 = r6.ordinal()
            r6 = r7[r6]
            if (r6 != r4) goto L4d
            com.quizlet.generated.enums.G0 r6 = com.quizlet.generated.enums.G0.PRACTICE_TEST_UPLOAD
            goto L4f
        L4d:
            com.quizlet.generated.enums.G0 r6 = com.quizlet.generated.enums.G0.STUDY_GUIDE_UPLOAD
        L4f:
            java.lang.String r6 = r6.a()
            kotlin.p r7 = kotlin.r.b     // Catch: java.lang.Throwable -> L28
            java.lang.Object r7 = r5.b     // Catch: java.lang.Throwable -> L28
            com.google.android.material.floatingactionbutton.c r7 = (com.google.android.material.floatingactionbutton.c) r7     // Catch: java.lang.Throwable -> L28
            r0.l = r4     // Catch: java.lang.Throwable -> L28
            java.lang.Object r7 = r7.b     // Catch: java.lang.Throwable -> L28
            com.quizlet.data.repository.classfolder.e r7 = (com.quizlet.data.repository.classfolder.e) r7     // Catch: java.lang.Throwable -> L28
            com.quizlet.remote.model.entitlements.a r2 = new com.quizlet.remote.model.entitlements.a     // Catch: java.lang.Throwable -> L28
            r2.<init>(r7, r6, r3)     // Catch: java.lang.Throwable -> L28
            java.lang.Object r6 = r7.d     // Catch: java.lang.Throwable -> L28
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6     // Catch: java.lang.Throwable -> L28
            java.lang.Object r7 = kotlinx.coroutines.E.J(r6, r2, r0)     // Catch: java.lang.Throwable -> L28
            if (r7 != r1) goto L6f
            return r1
        L6f:
            com.quizlet.data.model.S r7 = (com.quizlet.data.model.S) r7     // Catch: java.lang.Throwable -> L28
            kotlin.p r6 = kotlin.r.b     // Catch: java.lang.Throwable -> L28
            goto L7a
        L74:
            kotlin.p r7 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r6)
        L7a:
            boolean r6 = r7 instanceof kotlin.q
            if (r6 == 0) goto L7f
            goto L80
        L7f:
            r3 = r7
        L80:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.l.m(com.quizlet.data.model.m2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.learn.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.learn.a r0 = (com.quizlet.data.interactor.learn.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.learn.a r0 = new com.quizlet.data.interactor.learn.a
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            return r6
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            androidx.work.impl.model.l r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.generated.enums.I0 r6 = com.quizlet.generated.enums.I0.LEARN_MOBILE_NATIVE_IMPROVEMENTS
            r0.j = r5
            r0.m = r4
            java.lang.Object r2 = r5.b
            com.quizlet.data.repository.activitycenter.b r2 = (com.quizlet.data.repository.activitycenter.b) r2
            java.lang.Object r6 = r2.j(r6, r0)
            if (r6 != r1) goto L4c
            goto L64
        L4c:
            r2 = r5
        L4d:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L66
            java.lang.Object r6 = r2.c
            com.quizlet.data.repository.user.a r6 = (com.quizlet.data.repository.user.a) r6
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = r6.j(r0)
            if (r6 != r1) goto L65
        L64:
            return r1
        L65:
            return r6
        L66:
            java.lang.Boolean r6 = java.lang.Boolean.FALSE
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.l.n(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        switch (this.a) {
            case 1:
                break;
            default:
                AbstractC3242q6.h("Camera surface session should only fail with request cancellation. Instead failed due to:\n" + th, th instanceof androidx.camera.core.h0);
                ((androidx.core.util.a) this.b).accept(new C0157i(1, (Surface) this.c));
                break;
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 1:
                ((androidx.camera.camera2.internal.C) this.c).m.remove((V) this.b);
                int iK = AbstractC0147y.k(((androidx.camera.camera2.internal.C) this.c).H);
                if (iK != 1 && iK != 4) {
                    if (iK == 5 || (iK == 6 && ((androidx.camera.camera2.internal.C) this.c).k != 0)) {
                        ((androidx.camera.camera2.internal.C) this.c).t("Camera reopen required. Checking if the current camera can be closed safely.");
                    }
                }
                if (((androidx.camera.camera2.internal.C) this.c).m.isEmpty()) {
                    androidx.camera.camera2.internal.C c = (androidx.camera.camera2.internal.C) this.c;
                    if (c.j != null) {
                        c.t("closing camera");
                        ((androidx.camera.camera2.internal.C) this.c).j.close();
                        ((androidx.camera.camera2.internal.C) this.c).j = null;
                        break;
                    }
                }
                break;
            default:
                ((androidx.core.util.a) this.b).accept(new C0157i(0, (Surface) this.c));
                break;
        }
    }

    public void p(Bundle bundle) {
        Locale locale = Locale.US;
        Objects.toString(bundle);
        Log.isLoggable("FirebaseCrashlytics", 2);
        String string = bundle.getString("name");
        if (string != null) {
            Bundle bundle2 = bundle.getBundle("params");
            if (bundle2 == null) {
                bundle2 = new Bundle();
            }
            com.google.firebase.crashlytics.internal.analytics.b bVar = "clx".equals(bundle2.getString("_o")) ? (com.quizlet.data.repository.user.a) this.b : (androidx.webkit.internal.p) this.c;
            if (bVar == null) {
                return;
            }
            bVar.h(bundle2, string);
        }
    }

    public com.android.volley.h q(com.android.volley.l lVar) throws IOException, VolleyError {
        byte[] bArr;
        v vVar;
        String str;
        int timeoutMs;
        Map map;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        while (true) {
            com.android.volley.toolbox.a aVar = null;
            try {
                com.android.volley.a cacheEntry = lVar.getCacheEntry();
                if (cacheEntry == null) {
                    map = Collections.EMPTY_MAP;
                } else {
                    HashMap map2 = new HashMap();
                    String str2 = cacheEntry.b;
                    if (str2 != null) {
                        map2.put("If-None-Match", str2);
                    }
                    long j = cacheEntry.d;
                    if (j > 0) {
                        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
                        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
                        map2.put("If-Modified-Since", simpleDateFormat.format(new Date(j)));
                    }
                    map = map2;
                }
                com.android.volley.toolbox.a aVarU = ((com.quizlet.shared.usecase.srs.a) this.b).u(lVar, map);
                try {
                    int i = aVarU.a;
                    List listUnmodifiableList = Collections.unmodifiableList(aVarU.b);
                    if (i == 304) {
                        return AbstractC3562y.a(lVar, SystemClock.elapsedRealtime() - jElapsedRealtime, listUnmodifiableList);
                    }
                    com.android.volley.toolbox.e eVar = (com.android.volley.toolbox.e) aVarU.d;
                    if (eVar == null) {
                        eVar = null;
                    }
                    byte[] bArrB = eVar != null ? AbstractC3562y.b(eVar, aVarU.c, (com.android.volley.toolbox.a) this.c) : new byte[0];
                    try {
                        long jElapsedRealtime2 = SystemClock.elapsedRealtime() - jElapsedRealtime;
                        if (com.android.volley.y.a || jElapsedRealtime2 > 3000) {
                            com.android.volley.y.a("HTTP response for request=<%s> [lifetime=%d], [size=%s], [rc=%d], [retryCount=%s]", lVar, Long.valueOf(jElapsedRealtime2), bArrB != null ? Integer.valueOf(bArrB.length) : "null", Integer.valueOf(i), Integer.valueOf(((com.android.volley.d) lVar.getRetryPolicy()).b));
                        }
                        if (i < 200 || i > 299) {
                            throw new IOException();
                        }
                        return new com.android.volley.h(i, bArrB, false, SystemClock.elapsedRealtime() - jElapsedRealtime, listUnmodifiableList);
                    } catch (IOException e) {
                        e = e;
                        aVar = aVarU;
                        bArr = bArrB;
                        if (e instanceof SocketTimeoutException) {
                            vVar = new v(7, "socket", new TimeoutError());
                        } else {
                            if (e instanceof MalformedURLException) {
                                throw new RuntimeException("Bad URL " + lVar.getUrl(), e);
                            }
                            if (aVar != null) {
                                int i2 = aVar.a;
                                com.android.volley.y.b("Unexpected response code %d for %s", Integer.valueOf(i2), lVar.getUrl());
                                if (bArr != null) {
                                    com.android.volley.h hVar = new com.android.volley.h(i2, bArr, false, SystemClock.elapsedRealtime() - jElapsedRealtime, Collections.unmodifiableList(aVar.b));
                                    if (i2 == 401 || i2 == 403) {
                                        vVar = new v(7, "auth", new AuthFailureError(hVar));
                                    } else {
                                        if (i2 >= 400 && i2 <= 499) {
                                            throw new ClientError(hVar);
                                        }
                                        if (i2 < 500 || i2 > 599 || !lVar.shouldRetryServerErrors()) {
                                            throw new ServerError(hVar);
                                        }
                                        vVar = new v(7, "server", new ServerError(hVar));
                                    }
                                } else {
                                    vVar = new v(7, "network", new NetworkError());
                                }
                            } else {
                                if (!lVar.shouldRetryConnectionErrors()) {
                                    throw new NoConnectionError(e);
                                }
                                vVar = new v(7, "connection", new NoConnectionError());
                            }
                        }
                        str = (String) vVar.b;
                        com.android.volley.v retryPolicy = lVar.getRetryPolicy();
                        timeoutMs = lVar.getTimeoutMs();
                        try {
                            VolleyError volleyError = (VolleyError) vVar.c;
                            com.android.volley.d dVar = (com.android.volley.d) retryPolicy;
                            int i3 = dVar.b + 1;
                            dVar.b = i3;
                            int i4 = dVar.a;
                            dVar.a = i4 + ((int) (i4 * dVar.d));
                            if (i3 > dVar.c) {
                                throw volleyError;
                            }
                            lVar.addMarker(str + "-retry [timeout=" + timeoutMs + "]");
                        } catch (VolleyError e2) {
                            lVar.addMarker(str + "-timeout-giveup [timeout=" + timeoutMs + "]");
                            throw e2;
                        }
                    }
                } catch (IOException e3) {
                    e = e3;
                    bArr = null;
                    aVar = aVarU;
                }
            } catch (IOException e4) {
                e = e4;
                bArr = null;
            }
            lVar.addMarker(str + "-retry [timeout=" + timeoutMs + "]");
        }
    }

    public io.reactivex.rxjava3.core.p r() {
        return ((com.quizlet.data.repository.login.a) this.b).j((c) this.c);
    }

    public void s(View view, float[] fArr) {
        Object parent = view.getParent();
        boolean z = parent instanceof View;
        float[] fArr2 = (float[]) this.b;
        if (z) {
            s((View) parent, fArr);
            androidx.compose.ui.graphics.J.d(fArr2);
            androidx.compose.ui.graphics.J.h(fArr2, -view.getScrollX(), -view.getScrollY());
            N.D(fArr, fArr2);
            float left = view.getLeft();
            float top = view.getTop();
            androidx.compose.ui.graphics.J.d(fArr2);
            androidx.compose.ui.graphics.J.h(fArr2, left, top);
            N.D(fArr, fArr2);
        } else {
            int[] iArr = (int[]) this.c;
            view.getLocationInWindow(iArr);
            androidx.compose.ui.graphics.J.d(fArr2);
            androidx.compose.ui.graphics.J.h(fArr2, -view.getScrollX(), -view.getScrollY());
            N.D(fArr, fArr2);
            float f = iArr[0];
            float f2 = iArr[1];
            androidx.compose.ui.graphics.J.d(fArr2);
            androidx.compose.ui.graphics.J.h(fArr2, f, f2);
            N.D(fArr, fArr2);
        }
        Matrix matrix = view.getMatrix();
        if (matrix.isIdentity()) {
            return;
        }
        F.u(matrix, fArr2);
        N.D(fArr, fArr2);
    }

    public /* synthetic */ l(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public /* synthetic */ l(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public l(c folderWithCreatorInClassLocal, com.quizlet.data.interactor.progress.c folderWithCreatorInClassRemote) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(folderWithCreatorInClassLocal, "folderWithCreatorInClassLocal");
        Intrinsics.checkNotNullParameter(folderWithCreatorInClassRemote, "folderWithCreatorInClassRemote");
        this.b = folderWithCreatorInClassLocal;
        this.c = folderWithCreatorInClassRemote;
    }

    public l(com.quizlet.data.repository.activitycenter.b eligibilityFeature, com.quizlet.data.repository.user.a feature) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(eligibilityFeature, "eligibilityFeature");
        Intrinsics.checkNotNullParameter(feature, "feature");
        this.b = eligibilityFeature;
        this.c = feature;
    }

    public l(com.quizlet.data.repository.classfolder.e repository, c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public l(EventLogger eventLogger, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d saveLearnSettingsUseCase) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(saveLearnSettingsUseCase, "saveLearnSettingsUseCase");
        this.b = eventLogger;
        this.c = saveLearnSettingsUseCase;
    }

    public l(com.google.android.material.floatingactionbutton.c getEntitlementUseCase, UserInfoCache userInfoCache) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(getEntitlementUseCase, "getEntitlementUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = getEntitlementUseCase;
        this.c = userInfoCache;
    }

    public l(c dataSource, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c remoteQuestionMapper, com.quizlet.quizletandroid.logging.initializer.a meteringInfoMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(remoteQuestionMapper, "remoteQuestionMapper");
        Intrinsics.checkNotNullParameter(meteringInfoMapper, "meteringInfoMapper");
        this.b = dataSource;
        this.c = remoteQuestionMapper;
    }

    public l(com.quizlet.data.repository.login.a usConstrainedFeature, c userProperties) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(usConstrainedFeature, "usConstrainedFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.b = usConstrainedFeature;
        this.c = userProperties;
    }

    public l() {
        this.a = 8;
        this.b = new AtomicReference();
        this.c = new C0208f(0);
    }

    public l(l1 repository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public l(com.quizlet.infra.legacysyncengine.managers.g livePreferencesManager) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(livePreferencesManager, "livePreferencesManager");
        this.b = livePreferencesManager;
    }

    public l(m0 savedState, com.quizlet.quizletandroid.ui.studymodes.grader.b studiablQuestionGraderProvider, com.quizlet.features.questiontypes.grading.a smartGradingLogger) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(savedState, "savedState");
        Intrinsics.checkNotNullParameter(studiablQuestionGraderProvider, "studiablQuestionGraderProvider");
        Intrinsics.checkNotNullParameter(smartGradingLogger, "smartGradingLogger");
        this.b = smartGradingLogger;
        Object objA = savedState.a("ARG_SESSION_ID");
        if (objA != null) {
            long jLongValue = ((Number) objA).longValue();
            z1 z1Var = A1.Companion;
            Object objA2 = savedState.a("ARG_STUDY_MODE_TYPE");
            if (objA2 != null) {
                int iIntValue = ((Number) objA2).intValue();
                z1Var.getClass();
                this.c = studiablQuestionGraderProvider.a(z1.a(iIntValue));
                smartGradingLogger.c = Long.valueOf(jLongValue);
                return;
            }
            throw new IllegalArgumentException("Required value was null.");
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    public l(WorkDatabase_Impl database) {
        this.a = 0;
        this.b = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.c = new b(database, 3);
    }

    public l(com.quizlet.shared.usecase.srs.a aVar) {
        this.a = 7;
        com.android.volley.toolbox.a aVar2 = new com.android.volley.toolbox.a();
        this.b = aVar;
        this.c = aVar2;
    }

    public l(M m) {
        this.a = 3;
        this.b = m;
        this.c = new LinkedHashMap();
    }

    public l(float[] fArr) {
        this.a = 4;
        this.b = fArr;
        this.c = new int[2];
    }
}

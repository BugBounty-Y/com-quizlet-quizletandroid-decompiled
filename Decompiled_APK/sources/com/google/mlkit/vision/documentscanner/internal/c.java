package com.google.mlkit.vision.documentscanner.internal;

import android.content.Intent;
import android.text.TextUtils;
import androidx.datastore.core.InterfaceC1076h;
import androidx.recyclerview.widget.C1372j;
import androidx.work.impl.model.v;
import assistantMode.enums.m;
import com.android.billingclient.api.Purchase;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.measurement.T1;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3722s6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3602d5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;
import com.j256.ormlite.dao.Dao;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.api.model.IPurchase;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.V1;
import com.quizlet.data.model.Z1;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.O1;
import com.quizlet.local.datastore.preferences.C4561a;
import com.quizlet.local.datastore.preferences.C4565c;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.quizletandroid.t;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.i;
import io.reactivex.rxjava3.core.k;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.single.g;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.StringsKt;
import kotlin.u;
import okhttp3.o;
import okhttp3.s;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements com.google.android.gms.tasks.d, IPurchase, h, com.quizlet.local.ormlite.database.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static JSONObject b(Map map, JSONObject jSONObject) throws JSONException {
        JSONArray jSONArrayNames;
        if (jSONObject != null && (jSONArrayNames = jSONObject.names()) != null) {
            if (map.isEmpty()) {
                return jSONObject;
            }
            JSONObject jSONObject2 = new JSONObject();
            for (int i = 0; i < jSONArrayNames.length(); i++) {
                try {
                    String string = jSONArrayNames.getString(i);
                    JSONObject jSONObject3 = jSONObject.getJSONObject(string);
                    if (!retrofit2.adapter.rxjava3.d.o(jSONObject3) && jSONObject3.has("CookiesCategoryIds")) {
                        JSONArray jSONArray = jSONObject3.getJSONArray("CookiesCategoryIds");
                        int i2 = 0;
                        while (true) {
                            if (i2 >= jSONArray.length()) {
                                break;
                            }
                            if (map.containsKey(jSONArray.getString(i2).trim())) {
                                jSONObject2.put(string, jSONObject3);
                                break;
                            }
                            i2++;
                        }
                    }
                } catch (JSONException e) {
                    W.a("General Vendor: error on filtering", e, "GeneralVendors", 6);
                }
            }
            OTLogger.c("GeneralVendors", 4, "General Vendor: filtered vendors:" + jSONObject2);
            return jSONObject2;
        }
        return new JSONObject();
    }

    public JSONObject a() {
        String string = ((com.onetrust.otpublishers.headless.Internal.Preferences.d) this.b).b().getString("OT_GENERAL_VENDORS", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                W.a("Something went wrong while parsing savedGeneral Vendors: ", e, "GeneralVendors", 3);
            }
        }
        return new JSONObject();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        StudiableAudio studiableAudio;
        StudiableAudio studiableAudio2;
        StudiableImage studiableImage;
        Object next;
        switch (this.a) {
            case 5:
                com.quizlet.data.repository.explanations.exercise.b bVar = (com.quizlet.data.repository.explanations.exercise.b) this.b;
                return (k) ((com.quizlet.data.interactor.progress.d) bVar.a).invoke((r) bVar.b);
            case 10:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.classfolder.e) this.b).d).j("Network error trying to fetch ClassFolders", e);
                return E.a;
            case 11:
                return (p) this.b;
            case 12:
                List<StudySetWithCreator> list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (StudySetWithCreator studySetWithCreator : list) {
                    ((com.quizlet.data.repository.studysetwithcreator.d) this.b).getClass();
                    arrayList.add(new Z1(studySetWithCreator.a, studySetWithCreator.b, V1.b));
                }
                return arrayList;
            case 13:
                Throwable e2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.user.e) this.b).d).j("no cached object", e2);
                return E.a;
            case 17:
                C1 defaultStudyPath = (C1) obj;
                Intrinsics.checkNotNullParameter(defaultStudyPath, "defaultStudyPath");
                return p.f(f.a((f) this.b, defaultStudyPath));
            case EventType.AUDIO /* 23 */:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                List<DBTerm> list2 = (List) pair.a;
                List list3 = (List) pair.b;
                ((com.quizlet.remote.model.notes.e) this.b).getClass();
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                for (DBTerm dBTerm : list2) {
                    Intrinsics.checkNotNullParameter(dBTerm, "<this>");
                    String wordAudioUrl = dBTerm.getWordAudioUrl();
                    if (wordAudioUrl == null || StringsKt.O(wordAudioUrl)) {
                        studiableAudio = null;
                    } else {
                        String wordAudioUrl2 = dBTerm.getWordAudioUrl();
                        Intrinsics.d(wordAudioUrl2);
                        studiableAudio = new StudiableAudio(wordAudioUrl2);
                    }
                    m mVar = m.b;
                    String word = dBTerm.getWord();
                    if (word == null) {
                        word = "";
                    }
                    O1 o1 = O1.WORD;
                    com.quizlet.studiablemodels.e eVar = new com.quizlet.studiablemodels.e(mVar, new StudiableText(word, dBTerm.getLanguageCode(o1), dBTerm.getRichText(o1)), null, studiableAudio);
                    String definitionAudioUrl = dBTerm.getDefinitionAudioUrl();
                    if (definitionAudioUrl == null || StringsKt.O(definitionAudioUrl)) {
                        studiableAudio2 = null;
                    } else {
                        String definitionAudioUrl2 = dBTerm.getDefinitionAudioUrl();
                        Intrinsics.d(definitionAudioUrl2);
                        studiableAudio2 = new StudiableAudio(definitionAudioUrl2);
                    }
                    DBImage definitionImage = dBTerm.getDefinitionImage();
                    boolean z = false;
                    if (definitionImage != null) {
                        String smallUrl = definitionImage.getSmallUrl();
                        String mediumUrl = definitionImage.getMediumUrl();
                        String largeUrl = definitionImage.getLargeUrl();
                        Integer width = definitionImage.getWidth();
                        int iIntValue = width != null ? width.intValue() : 0;
                        Integer height = definitionImage.getHeight();
                        studiableImage = new StudiableImage(smallUrl, iIntValue, mediumUrl, largeUrl, height != null ? height.intValue() : 0);
                    } else {
                        studiableImage = null;
                    }
                    m mVar2 = m.c;
                    String definition = dBTerm.getDefinition();
                    String str = definition != null ? definition : "";
                    O1 o12 = O1.DEFINITION;
                    i iVar = new i(dBTerm.getId(), eVar, new com.quizlet.studiablemodels.e(mVar2, new StudiableText(str, dBTerm.getLanguageCode(o12), dBTerm.getRichText(o12)), studiableImage, studiableAudio2), null, false);
                    Iterator it2 = list3.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            next = it2.next();
                            if (((DBSelectedTerm) next).getTermId() == dBTerm.getId()) {
                            }
                        } else {
                            next = null;
                        }
                    }
                    if (next != null) {
                        z = true;
                    }
                    arrayList2.add(new com.quizlet.learn.checkpoint.data.d(iVar, z));
                }
                ArrayList arrayList3 = new ArrayList();
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    Object next2 = it3.next();
                    arrayList3.add(next2);
                }
                return arrayList3;
            case EventType.CDN /* 26 */:
                List<DBGroupFolder> it4 = (List) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                int iA = U.a(C.q(it4, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                for (DBGroupFolder dBGroupFolder : it4) {
                    ((com.quizlet.local.ormlite.models.bookmark.a) this.b).getClass();
                    linkedHashMap.put(new com.quizlet.data.repository.classfolder.a(dBGroupFolder.getClassId(), dBGroupFolder.getFolderId()), Long.valueOf(dBGroupFolder.getLocalId()));
                }
                return linkedHashMap;
            case 27:
                List folderIds = (List) obj;
                Intrinsics.checkNotNullParameter(folderIds, "folderIds");
                return ((com.quizlet.local.ormlite.models.bookmark.a) this.b).b(folderIds);
            case 28:
                List studySets = (List) obj;
                Intrinsics.checkNotNullParameter(studySets, "studySets");
                ArrayList arrayList4 = new ArrayList(C.q(studySets, 10));
                Iterator it5 = studySets.iterator();
                while (it5.hasNext()) {
                    arrayList4.add(Long.valueOf(((StudySet) it5.next()).e));
                }
                com.quizlet.local.ormlite.models.studysetwithcreator.a aVar = (com.quizlet.local.ormlite.models.studysetwithcreator.a) this.b;
                return aVar.b.b(arrayList4).g(new com.quizlet.data.interactor.school.b(23, aVar, studySets));
            default:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.data.repository.set.f fVar = (com.quizlet.data.repository.set.f) this.b;
                return new io.reactivex.rxjava3.internal.operators.completable.m(((com.google.firebase.messaging.p) fVar.d).f(modelsWithIds), null, Boolean.TRUE, 0).g(new com.quizlet.data.repository.qclass.c(23, modelsWithIds, fVar));
        }
    }

    public String c(long j, com.quizlet.features.blocks.data.b state) {
        String string;
        String string2;
        String strB;
        Intrinsics.checkNotNullParameter(state, "state");
        String str = "https://quizlet.com/" + j + state.a;
        Intrinsics.checkNotNullParameter(str, "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, str);
        C1372j c1372jF = c1372j.d().f();
        boolean zQ = ((com.quizlet.data.repository.set.f) this.b).q();
        Intrinsics.checkNotNullParameter(c1372jF, "<this>");
        c1372jF.c("__injectedColorTheme", zQ ? "night" : "default");
        String string3 = c1372jF.toString();
        Intrinsics.checkNotNullParameter(string3, "<this>");
        s sVarC = T1.c(string3);
        ArrayList arrayList = sVarC.f;
        if (!arrayList.contains("oauthweb")) {
            Intrinsics.checkNotNullParameter("https://quizlet.com", "<this>");
            C1372j c1372j2 = new C1372j();
            c1372j2.l(null, "https://quizlet.com");
            C1372j c1372jF2 = c1372j2.d().f();
            Intrinsics.checkNotNullParameter("oauthweb", "pathSegment");
            c1372jF2.m("oauthweb", 0, 8, false, false);
            c1372jF2.b(CollectionsKt.S(arrayList, "/", null, null, null, 62));
            ArrayList arrayList2 = sVarC.g;
            if (arrayList2 == null) {
                string2 = null;
            } else {
                StringBuilder sb = new StringBuilder();
                o.i(arrayList2, sb);
                string2 = sb.toString();
            }
            c1372jF2.d = (string2 == null || (strB = o.b(0, 0, 219, string2, " \"'<>#", false)) == null) ? null : o.h(strB);
            string3 = c1372jF2.toString();
        }
        Intrinsics.checkNotNullParameter(string3, "<this>");
        s sVarC2 = T1.c(string3);
        ArrayList arrayList3 = sVarC2.f;
        if (arrayList3.contains("redirect")) {
            return string3;
        }
        boolean zContains = arrayList3.contains("oauthweb");
        ArrayList arrayList4 = new ArrayList();
        Iterator it2 = arrayList3.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (!Intrinsics.b((String) next, "oauthweb")) {
                arrayList4.add(next);
            }
        }
        String strS = CollectionsKt.S(arrayList4, "/", "/", null, null, 60);
        ArrayList arrayList5 = sVarC2.g;
        if (arrayList5 == null) {
            string = null;
        } else {
            StringBuilder sb2 = new StringBuilder();
            o.i(arrayList5, sb2);
            string = sb2.toString();
        }
        String strConcat = string != null ? "?".concat(string) : null;
        if (strConcat == null) {
            strConcat = "";
        }
        String str2 = strS + strConcat;
        Intrinsics.checkNotNullParameter("https://quizlet.com", "<this>");
        C1372j c1372j3 = new C1372j();
        c1372j3.l(null, "https://quizlet.com");
        C1372j c1372jF3 = c1372j3.d().f();
        if (zContains) {
            Intrinsics.checkNotNullParameter("oauthweb", "pathSegment");
            c1372jF3.m("oauthweb", 0, 8, false, false);
        }
        c1372jF3.b("redirect");
        c1372jF3.c("redir", str2);
        return c1372jF3.toString();
    }

    public Object d(kotlin.coroutines.jvm.internal.c cVar) {
        C4567d c4567d = (C4567d) this.b;
        Object objD = S6.d(c4567d.a, new C4561a(c4567d, null), cVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objD != aVar) {
            objD = Unit.a;
        }
        return objD == aVar ? objD : Unit.a;
    }

    public ArrayList e() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = ((ArrayList) this.b).iterator();
        while (it2.hasNext()) {
            arrayList.addAll(((com.quizlet.features.infra.legacyadapter.section.a) it2.next()).a);
        }
        return arrayList;
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        Object value = ((u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return com.quizlet.local.ormlite.util.b.a((Dao) value, models);
    }

    public io.reactivex.rxjava3.internal.operators.flowable.b g(com.quizlet.ads.c adUnit) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.google.firebase.tracing.a(2, this, adUnit), 3);
        Intrinsics.checkNotNullExpressionValue(bVar, "create(...)");
        return bVar;
    }

    @Override // com.quizlet.api.model.IPurchase
    public String getOrderId() {
        String strOptString = ((Purchase) this.b).c.optString(DBTermFields.Names.RANK);
        if (TextUtils.isEmpty(strOptString)) {
            return null;
        }
        return strOptString;
    }

    @Override // com.quizlet.api.model.IPurchase
    public String getPackageName() {
        String strOptString = ((Purchase) this.b).c.optString("packageName");
        Intrinsics.checkNotNullExpressionValue(strOptString, "getPackageName(...)");
        return strOptString;
    }

    @Override // com.quizlet.api.model.IPurchase
    public String getSku() {
        return AbstractC3722s6.d((Purchase) this.b);
    }

    @Override // com.quizlet.api.model.IPurchase
    public String getToken() {
        String strB = ((Purchase) this.b).b();
        Intrinsics.checkNotNullExpressionValue(strB, "getPurchaseToken(...)");
        return strB;
    }

    public int h() {
        Iterator it2 = ((ArrayList) this.b).iterator();
        int iA = 0;
        while (it2.hasNext()) {
            iA += ((com.quizlet.features.infra.legacyadapter.section.a) it2.next()).a();
        }
        return iA;
    }

    public com.quizlet.features.infra.legacyadapter.section.a i(int i) {
        Iterator it2 = ((ArrayList) this.b).iterator();
        while (it2.hasNext()) {
            com.quizlet.features.infra.legacyadapter.section.a aVar = (com.quizlet.features.infra.legacyadapter.section.a) it2.next();
            if (i < aVar.a()) {
                return aVar;
            }
            i -= aVar.a();
        }
        return null;
    }

    public int j(com.quizlet.features.infra.legacyadapter.section.a aVar) {
        if (aVar == null) {
            return -1;
        }
        Iterator it2 = ((ArrayList) this.b).iterator();
        int iA = 0;
        while (it2.hasNext()) {
            com.quizlet.features.infra.legacyadapter.section.a aVar2 = (com.quizlet.features.infra.legacyadapter.section.a) it2.next();
            if (aVar2.equals(aVar)) {
                return iA;
            }
            iA += aVar2.a();
        }
        return -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum k(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.termlist.repository.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.termlist.repository.a r0 = (com.quizlet.features.setpage.termlist.repository.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.setpage.termlist.repository.a r0 = new com.quizlet.features.setpage.termlist.repository.a
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L66
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            com.quizlet.local.datastore.preferences.d r7 = (com.quizlet.local.datastore.preferences.C4567d) r7
            java.lang.Long r5 = java.lang.Long.valueOf(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r5}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "set_page_%s_sort_option"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r5)
            androidx.datastore.core.h r6 = r7.a
            kotlinx.coroutines.flow.i r6 = r6.getData()
            com.quizlet.local.datastore.preferences.x r7 = new com.quizlet.local.datastore.preferences.x
            r2 = 2
            r7.<init>(r6, r5, r2)
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.r(r7, r0)
            if (r7 != r1) goto L66
            return r1
        L66:
            java.lang.Integer r7 = (java.lang.Integer) r7
            if (r7 != 0) goto L6d
            com.quizlet.features.setpage.termlist.data.m r5 = com.quizlet.features.setpage.termlist.data.m.a
            return r5
        L6d:
            kotlin.enums.b r5 = com.quizlet.features.setpage.termlist.data.m.c
            int r6 = r7.intValue()
            java.lang.Object r5 = kotlin.collections.CollectionsKt.O(r6, r5)
            com.quizlet.features.setpage.termlist.data.m r5 = (com.quizlet.features.setpage.termlist.data.m) r5
            if (r5 != 0) goto L7d
            com.quizlet.features.setpage.termlist.data.m r5 = com.quizlet.features.setpage.termlist.data.m.a
        L7d:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.vision.documentscanner.internal.c.k(long, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.e0
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.e0 r0 = (com.quizlet.local.datastore.preferences.e0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.e0 r0 = new com.quizlet.local.datastore.preferences.e0
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "user_completed_onboarding_flashcards_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r5)
            java.lang.Object r6 = r4.b
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r7 != r1) goto L63
            return r1
        L63:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            if (r5 == 0) goto L72
            boolean r5 = r5.booleanValue()
            goto L73
        L72:
            r5 = 0
        L73:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.vision.documentscanner.internal.c.l(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(long r11, boolean r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.studymode.test.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.studymode.test.a r0 = (com.quizlet.data.interactor.studymode.test.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.studymode.test.a r0 = new com.quizlet.data.interactor.studymode.test.a
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r14)     // Catch: java.lang.Exception -> L4f
            goto L4c
        L27:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r10.b     // Catch: java.lang.Exception -> L4f
            r5 = r14
            androidx.work.impl.model.v r5 = (androidx.work.impl.model.v) r5     // Catch: java.lang.Exception -> L4f
            r0.l = r3     // Catch: java.lang.Exception -> L4f
            com.quizlet.local.ormlite.models.studymode.test.a r4 = new com.quizlet.local.ormlite.models.studymode.test.a     // Catch: java.lang.Exception -> L4f
            r9 = 0
            r6 = r11
            r8 = r13
            r4.<init>(r5, r6, r8, r9)     // Catch: java.lang.Exception -> L4f
            java.lang.Object r11 = r5.c     // Catch: java.lang.Exception -> L4f
            kotlinx.coroutines.y r11 = (kotlinx.coroutines.AbstractC5040y) r11     // Catch: java.lang.Exception -> L4f
            java.lang.Object r14 = kotlinx.coroutines.E.J(r11, r4, r0)     // Catch: java.lang.Exception -> L4f
            if (r14 != r1) goto L4c
            return r1
        L4c:
            java.lang.Integer r14 = (java.lang.Integer) r14     // Catch: java.lang.Exception -> L4f
            return r14
        L4f:
            r11 = 0
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.vision.documentscanner.internal.c.m(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Object n(String str, kotlin.coroutines.jvm.internal.c cVar) {
        C4567d c4567d = (C4567d) this.b;
        Object objD = S6.d(c4567d.a, new C4565c(c4567d, str, null), cVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objD != aVar) {
            objD = Unit.a;
        }
        return objD == aVar ? objD : Unit.a;
    }

    public g o(androidx.work.impl.model.c userProps, Object obj) {
        com.quizlet.infra.legacysyncengine.features.properties.d contentProps = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        p pVarL = ((com.quizlet.shared.usecase.studiableMetadata.a) this.b).l(userProps);
        g gVarE = userProps.n().e(new com.lyft.android.scissors.b(contentProps, 14));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return com.google.android.gms.dynamite.d.b(pVarL, gVarE);
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        GmsDocumentScanningResult gmsDocumentScanningResult = (GmsDocumentScanningResult) obj;
        GmsDocumentScanningDelegateActivity gmsDocumentScanningDelegateActivity = (GmsDocumentScanningDelegateActivity) this.b;
        int iA = 0;
        if (gmsDocumentScanningResult == null) {
            gmsDocumentScanningDelegateActivity.setResult(0);
            gmsDocumentScanningDelegateActivity.q(EnumC3602d5.CANCELLED, 0);
            gmsDocumentScanningDelegateActivity.finish();
            return;
        }
        Intent intent = new Intent();
        intent.putExtra("extra_scanning_result", gmsDocumentScanningResult);
        gmsDocumentScanningDelegateActivity.setResult(-1, intent);
        List listA = gmsDocumentScanningResult.a();
        GmsDocumentScanningResult.Pdf pdfB = gmsDocumentScanningResult.b();
        if (listA != null) {
            iA = listA.size();
        } else if (pdfB != null) {
            iA = pdfB.a();
        }
        gmsDocumentScanningDelegateActivity.q(EnumC3602d5.NO_ERROR, iA);
        gmsDocumentScanningDelegateActivity.finish();
    }

    public c(v testScoreRepository) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(testScoreRepository, "testScoreRepository");
        this.b = testScoreRepository;
    }

    public c(C3 practiceTestRepository) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(practiceTestRepository, "practiceTestRepository");
        this.b = practiceTestRepository;
    }

    public c(EventLogger eventLogger) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = eventLogger;
    }

    public c(C4567d confirmationWallRepository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(confirmationWallRepository, "confirmationWallRepository");
        this.b = confirmationWallRepository;
    }

    public c(C4567d termListPreferencesDataStore, byte b) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(termListPreferencesDataStore, "termListPreferencesDataStore");
        this.b = termListPreferencesDataStore;
    }

    public c(com.quizlet.data.repository.qclass.c repository) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public c(Purchase purchase) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(purchase, "purchase");
        this.b = purchase;
    }

    public c(com.quizlet.data.repository.set.f nightThemeManager) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
        this.b = nightThemeManager;
    }

    public c(androidx.work.impl.r workManager) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(workManager, "workManager");
        this.b = workManager;
    }

    public c(com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
        this.b = globalAdFeature;
    }

    public c(Function0 onThemeClick) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(onThemeClick, "onThemeClick");
        this.b = onThemeClick;
    }

    public c() {
        this.a = 18;
        this.b = new ArrayList();
    }

    public c(DatabaseHelper database) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = l.b(new com.quizlet.local.ormlite.database.dao.a(database, 3));
    }

    public c(com.quizlet.infra.legacysyncengine.net.c loader) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = loader;
    }

    public c(t dtbAdRequestProvider) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(dtbAdRequestProvider, "dtbAdRequestProvider");
        this.b = dtbAdRequestProvider;
    }

    public c(InterfaceC1076h dataStore) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public c(com.quizlet.qutils.image.loading.a imageLoader) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.b = imageLoader;
    }
}

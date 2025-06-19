package com.google.android.gms.internal.mlkit_common;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import androidx.appcompat.view.menu.y;
import androidx.camera.camera2.internal.c0;
import com.facebook.FacebookException;
import com.facebook.Profile;
import com.facebook.internal.I;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.J3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.firebase.components.ComponentRegistrar;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.m2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class u implements y, I, com.google.android.gms.ads.internal.util.client.b, com.google.android.gms.measurement.internal.r, com.google.firebase.components.e, com.google.firebase.components.d, com.google.zxing.b {
    public static u b;
    public final /* synthetic */ int a;

    public /* synthetic */ u(int i) {
        this.a = i;
    }

    public static void d(com.onetrust.otpublishers.headless.UI.DataModels.c cVar, JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("customPreferences")) {
            ArrayList arrayList = new ArrayList();
            JSONArray jSONArray = jSONObject.getJSONArray("customPreferences");
            for (int i = 0; i < jSONArray.length(); i++) {
                com.onetrust.otpublishers.headless.UI.DataModels.b bVar = new com.onetrust.otpublishers.headless.UI.DataModels.b();
                bVar.f = new ArrayList();
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                if (jSONObject2.has("id")) {
                    bVar.a = jSONObject2.optString("id");
                }
                if (jSONObject2.has("name")) {
                    bVar.b = jSONObject2.optString("name");
                }
                if (jSONObject2.has(OTUXParamsKeys.OT_UX_DESCRIPTION)) {
                    bVar.c = jSONObject2.optString(OTUXParamsKeys.OT_UX_DESCRIPTION);
                }
                if (jSONObject2.has("selectionType")) {
                    bVar.d = jSONObject2.optString("selectionType");
                }
                if (jSONObject2.has("purposeId")) {
                    jSONObject2.optString("purposeId");
                }
                if (jSONObject2.has("customPreferenceOptions")) {
                    ArrayList arrayList2 = new ArrayList();
                    JSONArray jSONArray2 = jSONObject2.getJSONArray("customPreferenceOptions");
                    for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                        com.onetrust.otpublishers.headless.UI.DataModels.d dVar = new com.onetrust.otpublishers.headless.UI.DataModels.d();
                        JSONObject jSONObject3 = jSONArray2.getJSONObject(i2);
                        if (jSONObject3.has("id")) {
                            dVar.a = jSONObject3.optString("id");
                        }
                        if (jSONObject3.has("label")) {
                            dVar.e = jSONObject3.optString("label");
                        }
                        if (jSONObject3.has("order")) {
                            dVar.f = jSONObject3.optString("order");
                        }
                        if (jSONObject3.has("isDefault")) {
                            dVar.g = jSONObject3.optString("isDefault");
                        }
                        if (jSONObject3.has("canDelete")) {
                            dVar.b = jSONObject3.optString("canDelete");
                        }
                        if (jSONObject3.has("purposeOptionsId")) {
                            dVar.i = jSONObject3.optString("purposeOptionsId");
                        }
                        if (jSONObject3.has("purposeId")) {
                            dVar.j = jSONObject3.optString("purposeId");
                        }
                        if (jSONObject3.has("userConsentStatus")) {
                            dVar.h = jSONObject3.optString("userConsentStatus");
                        }
                        if (jSONObject3.has("customPreferenceId")) {
                            dVar.k = jSONObject3.optString("customPreferenceId");
                        }
                        arrayList2.add(dVar);
                    }
                    bVar.f = arrayList2;
                }
                arrayList.add(bVar);
            }
            cVar.j = arrayList;
        }
    }

    public static void g(com.onetrust.otpublishers.headless.UI.DataModels.c cVar, JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("topics")) {
            ArrayList arrayList = new ArrayList();
            JSONArray jSONArray = jSONObject.getJSONArray("topics");
            for (int i = 0; i < jSONArray.length(); i++) {
                com.onetrust.otpublishers.headless.UI.DataModels.e eVar = new com.onetrust.otpublishers.headless.UI.DataModels.e();
                eVar.b = new ArrayList();
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                if (jSONObject2.has("name")) {
                    eVar.a = jSONObject2.optString("name");
                }
                if (jSONObject2.has("options")) {
                    ArrayList arrayList2 = new ArrayList();
                    JSONArray jSONArray2 = jSONObject2.getJSONArray("options");
                    for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                        com.onetrust.otpublishers.headless.UI.DataModels.d dVar = new com.onetrust.otpublishers.headless.UI.DataModels.d();
                        JSONObject jSONObject3 = jSONArray2.getJSONObject(i2);
                        if (jSONObject3.has("id")) {
                            dVar.a = jSONObject3.optString("id");
                        }
                        if (jSONObject3.has("name")) {
                            dVar.c = jSONObject3.optString("name");
                        }
                        if (jSONObject3.has("integrationKey")) {
                            dVar.d = jSONObject3.optString("integrationKey");
                        }
                        if (jSONObject3.has("customPreferenceId")) {
                            dVar.i = jSONObject3.optString("customPreferenceId");
                        }
                        if (jSONObject3.has("purposeId")) {
                            dVar.j = jSONObject3.optString("purposeId");
                        }
                        if (jSONObject3.has("userConsentStatus")) {
                            dVar.h = jSONObject3.optString("userConsentStatus");
                        }
                        if (jSONObject3.has("purposeTopicId")) {
                            dVar.l = jSONObject3.optString("purposeTopicId");
                        }
                        arrayList2.add(dVar);
                    }
                    eVar.b = arrayList2;
                }
                arrayList.add(eVar);
            }
            cVar.i = arrayList;
        }
    }

    public static void h(com.onetrust.otpublishers.headless.UI.DataModels.c cVar, JSONObject jSONObject) {
        if (jSONObject.has("id")) {
            cVar.a = jSONObject.optString("id");
        }
        if (jSONObject.has("label")) {
            cVar.b = jSONObject.optString("label");
        }
        if (jSONObject.has(OTUXParamsKeys.OT_UX_DESCRIPTION)) {
            cVar.c = jSONObject.optString(OTUXParamsKeys.OT_UX_DESCRIPTION);
        }
        if (jSONObject.has("status")) {
            cVar.d = jSONObject.optString("status");
        }
        if (jSONObject.has("newVersionAvailable")) {
            cVar.e = jSONObject.optString("newVersionAvailable");
        }
        if (jSONObject.has(DBUserFields.Names.USER_UPGRADE_TYPE)) {
            cVar.f = jSONObject.optString(DBUserFields.Names.USER_UPGRADE_TYPE);
        }
        if (jSONObject.has("consentLifeSpan")) {
            cVar.g = jSONObject.optString("consentLifeSpan");
        }
        if (jSONObject.has("version")) {
            cVar.h = jSONObject.optString("version");
        }
        if (jSONObject.has("userConsentStatus")) {
            cVar.k = jSONObject.optString("userConsentStatus");
        }
    }

    public static Intent i(Context context, m2 source, String str, ArrayList arrayList, AddMaterialFolderData addMaterialFolderData, int i) {
        int i2 = UploadNotesActivity.i;
        if ((i & 4) != 0) {
            str = null;
        }
        if ((i & 8) != 0) {
            arrayList = null;
        }
        if ((i & 16) != 0) {
            addMaterialFolderData = null;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(source, "source");
        Intent intent = new Intent(context, (Class<?>) UploadNotesActivity.class);
        intent.putExtra("source", source);
        intent.putExtra("text", str);
        intent.putExtra("uris", arrayList);
        intent.putExtra("addMaterialFolderData", addMaterialFolderData);
        return intent;
    }

    public static boolean j(QuestionSettings initial, QuestionSettings modified, boolean z) {
        Intrinsics.checkNotNullParameter(initial, "initial");
        Intrinsics.checkNotNullParameter(modified, "modified");
        return (Intrinsics.b(initial.b, modified.b) && Intrinsics.b(initial.a, modified.a) && initial.d == modified.d && initial.e == modified.e && initial.f == modified.f && initial.h == modified.h && initial.i == modified.i && initial.n == modified.n && initial.q == modified.q && initial.r == modified.r && initial.p == modified.p && !z) ? false : true;
    }

    @Override // com.google.firebase.components.e
    public List a(ComponentRegistrar componentRegistrar) {
        ArrayList arrayList = new ArrayList();
        for (com.google.firebase.components.a aVar : componentRegistrar.getComponents()) {
            String str = aVar.a;
            if (str != null) {
                com.google.firebase.tracing.a aVar2 = new com.google.firebase.tracing.a(0, str, aVar);
                aVar = new com.google.firebase.components.a(str, aVar.b, aVar.c, aVar.d, aVar.e, aVar2, aVar.g);
            }
            arrayList.add(aVar);
        }
        return arrayList;
    }

    @Override // com.facebook.internal.I
    public void b(JSONObject jSONObject) {
        String strOptString = jSONObject != null ? jSONObject.optString("id") : null;
        if (strOptString == null) {
            Log.w("Profile", "No user ID returned on Me request");
            return;
        }
        String strOptString2 = jSONObject.optString("link");
        String strOptString3 = jSONObject.optString("profile_picture", null);
        com.facebook.h.f.u().a(new Profile(strOptString, jSONObject.optString("first_name"), jSONObject.optString("middle_name"), jSONObject.optString("last_name"), jSONObject.optString("name"), strOptString2 != null ? Uri.parse(strOptString2) : null, strOptString3 != null ? Uri.parse(strOptString3) : null), true);
    }

    @Override // com.facebook.internal.I
    public void c(FacebookException facebookException) {
        Log.e("Profile", "Got unexpected exception: " + facebookException);
    }

    @Override // androidx.appcompat.view.menu.y
    public void e(androidx.appcompat.view.menu.n nVar, boolean z) {
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.sdkinternal.b(0);
    }

    public io.reactivex.rxjava3.core.p k(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        return com.google.android.gms.dynamite.d.f(userProps.t(), userProps.s());
    }

    /* JADX WARN: Code restructure failed: missing block: B:72:0x00ec, code lost:
    
        r6 = r12;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:334:0x0614  */
    /* JADX WARN: Removed duplicated region for block: B:381:0x06b3  */
    /* JADX WARN: Removed duplicated region for block: B:411:0x072b  */
    /* JADX WARN: Removed duplicated region for block: B:412:0x072e  */
    /* JADX WARN: Removed duplicated region for block: B:471:0x00ee A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00ce  */
    @Override // com.google.zxing.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.zxing.common.b l(java.lang.String r31, int r32, int r33, int r34, java.util.EnumMap r35) throws com.google.zxing.WriterException, java.io.UnsupportedEncodingException {
        /*
            Method dump skipped, instructions count: 2216
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_common.u.l(java.lang.String, int, int, int, java.util.EnumMap):com.google.zxing.common.b");
    }

    @Override // androidx.appcompat.view.menu.y
    public boolean z(androidx.appcompat.view.menu.n nVar) {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.util.client.b
    public com.google.android.gms.ads.internal.util.client.j zza(String str) {
        new com.amazon.aps.shared.util.a(str, 2).start();
        return com.google.android.gms.ads.internal.util.client.j.a;
    }

    public /* synthetic */ u(com.google.android.gms.ads.internal.util.client.c cVar) {
        this.a = 9;
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 11:
                List list = AbstractC3893t.a;
                W3.b.get();
                Boolean bool = (Boolean) Y3.c.b();
                bool.getClass();
                return bool;
            case 12:
                List list2 = AbstractC3893t.a;
                Boolean bool2 = (Boolean) J3.a.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.h0.b()).longValue());
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.L.b()).longValue());
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.e.b();
                l.getClass();
                return l;
            case 16:
                List list6 = AbstractC3893t.a;
                B3.b.get();
                return Integer.valueOf((int) ((Long) D3.d.b()).longValue());
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.B.b();
        }
    }
}

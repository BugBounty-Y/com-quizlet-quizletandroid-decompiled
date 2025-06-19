package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.quizlet.db.data.models.base.Comparators;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.x4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3760x4 {
    public static com.perimeterx.mobile_sdk.doctor_app.model.d a(JSONObject json) throws JSONException {
        com.perimeterx.mobile_sdk.doctor_app.model.i iVar;
        com.perimeterx.mobile_sdk.doctor_app.f fVar;
        com.perimeterx.mobile_sdk.doctor_app.f fVar2;
        Intrinsics.checkNotNullParameter(json, "json");
        try {
            Date date = !json.isNull("date") ? com.perimeterx.mobile_sdk.doctor_app.model.d.h.parse(json.getString("date")) : null;
            String string = json.getString("uuid");
            boolean z = json.getBoolean("startOnLaunchOK");
            boolean z2 = json.getBoolean("vidOK");
            com.perimeterx.mobile_sdk.doctor_app.model.b bVarA = !json.isNull("nativeSummary") ? AbstractC3752w4.a(new JSONObject(json.getString("nativeSummary"))) : null;
            if (json.isNull("webViewSummary")) {
                iVar = null;
            } else {
                JSONObject json2 = new JSONObject(json.getString("webViewSummary"));
                Intrinsics.checkNotNullParameter(json2, "json");
                try {
                    boolean z3 = json2.getBoolean("webViewSynced");
                    boolean z4 = json2.getBoolean("challengeShown");
                    boolean z5 = json2.getBoolean("challengeDismissed");
                    boolean z6 = json2.getBoolean("mobileDataSet");
                    com.perimeterx.mobile_sdk.doctor_app.model.i iVar2 = new com.perimeterx.mobile_sdk.doctor_app.model.i();
                    iVar2.a = z3;
                    iVar2.b = z4;
                    iVar2.c = z5;
                    iVar2.d = z6;
                    iVar = iVar2;
                } catch (Exception unused) {
                }
            }
            if (json.isNull("product")) {
                fVar = null;
            } else {
                com.quizlet.shared.usecase.folderstudymaterials.a aVar = com.perimeterx.mobile_sdk.doctor_app.f.a;
                String value = json.getString("product");
                Intrinsics.checkNotNullExpressionValue(value, "getString(...)");
                aVar.getClass();
                Intrinsics.checkNotNullParameter(value, "value");
                if (Intrinsics.b(value, "bot defender")) {
                    fVar2 = com.perimeterx.mobile_sdk.doctor_app.f.b;
                } else {
                    if (Intrinsics.b(value, "account defender")) {
                        fVar2 = com.perimeterx.mobile_sdk.doctor_app.f.c;
                    }
                    fVar = null;
                }
                fVar = fVar2;
            }
            Intrinsics.d(string);
            return new com.perimeterx.mobile_sdk.doctor_app.model.d(string, date, z, z2, bVarA, iVar, fVar);
        } catch (Exception unused2) {
            return null;
        }
    }

    public static final List b(List list, boolean z) {
        ArrayList arrayListM = assistantMode.refactored.a.m("groupMemberships", list);
        for (Object obj : list) {
            DBGroupMembership dBGroupMembership = (DBGroupMembership) obj;
            DBGroup group = dBGroupMembership.getGroup();
            boolean z2 = false;
            if (group != null) {
                boolean z3 = dBGroupMembership.isInvolved() && !group.getDeleted();
                if (!z) {
                    z2 = z3;
                } else if (z3 && (!group.getAdminOnly() || dBGroupMembership.isAdmin())) {
                    z2 = true;
                }
            }
            if (z2) {
                arrayListM.add(obj);
            }
        }
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(arrayListM, 10));
        Iterator it2 = arrayListM.iterator();
        while (it2.hasNext()) {
            arrayList.add(((DBGroupMembership) it2.next()).getGroup());
        }
        return CollectionsKt.n0(arrayList, Comparators.DEFAULT_DESC);
    }
}

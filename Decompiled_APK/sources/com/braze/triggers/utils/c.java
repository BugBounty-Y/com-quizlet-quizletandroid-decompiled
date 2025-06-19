package com.braze.triggers.utils;

import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.communication.dust.j;
import com.braze.managers.C1500m;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.support.BrazeLogger;
import com.braze.support.n;
import com.braze.support.w;
import com.braze.support.x;
import com.braze.triggers.actions.f;
import com.braze.triggers.actions.h;
import com.braze.triggers.managers.i;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();
    public static final String b = BrazeLogger.getBrazeLogTag((Class<?>) c.class);

    public static final String a(String str) {
        return AbstractC1475a.a("Received templated message Json with unknown type: ", str, ". Not parsing.");
    }

    public static final String b(String str) {
        return AbstractC1475a.a("Received triggered condition Json with unknown type: ", str, ". Not parsing.");
    }

    public static final String c(String str) {
        return AbstractC1484j.a("Received unknown trigger type: ", str);
    }

    public static InAppMessageBase a(JSONObject jSONObject, C1500m brazeManager) throws JSONException {
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        try {
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new j(jSONObject, 21), 8, (Object) null);
        }
        if (jSONObject == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(13), 14, (Object) null);
            return null;
        }
        String string = jSONObject.getString(DBUserFields.Names.USER_UPGRADE_TYPE);
        if (!Intrinsics.b(string, "inapp")) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(string, 22), 12, (Object) null);
            return null;
        }
        JSONObject jSONObject2 = jSONObject.getJSONObject("data");
        if (jSONObject2 == null) {
            return null;
        }
        return n.a(jSONObject2, brazeManager);
    }

    public static final String b(JSONArray jSONArray) {
        return "Failed to deserialize triggered actions Json array: " + jSONArray;
    }

    public static final String c() {
        return "Triggered actions Json array was null. Not de-serializing triggered actions.";
    }

    public final h b(JSONObject actionJson, C1500m brazeManager) throws JSONException {
        Intrinsics.checkNotNullParameter(actionJson, "actionJson");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        try {
            String string = actionJson.getString(DBUserFields.Names.USER_UPGRADE_TYPE);
            if (Intrinsics.b(string, "inapp")) {
                return new com.braze.triggers.actions.c(actionJson, brazeManager);
            }
            if (Intrinsics.b(string, "templated_iam")) {
                return new f(actionJson, brazeManager);
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new w(string, 23), 6, (Object) null);
            return null;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new j(actionJson, 22), 8, (Object) null);
            return null;
        }
    }

    public static final String a() {
        return "Templated message Json was null. Not de-serializing templated message.";
    }

    public static final String a(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Encountered exception processing templated message: ", jSONObject);
    }

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to deserialize triggered action Json: ", jSONObject);
    }

    public static final String b() {
        return "Received null or blank trigger condition Json. Not parsing.";
    }

    public final ArrayList a(JSONArray jSONArray, C1500m brazeManager) {
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        try {
            if (jSONArray == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(12), 14, (Object) null);
                return null;
            }
            ArrayList arrayList = new ArrayList();
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                JSONObject jSONObject = jSONArray.getJSONObject(i);
                Intrinsics.d(jSONObject);
                h hVarB = b(jSONObject, brazeManager);
                if (hVarB != null) {
                    arrayList.add(hVarB);
                }
            }
            return arrayList;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, b, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new x(1, jSONArray), 8, (Object) null);
            return null;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00d5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList a(org.json.JSONArray r13) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 274
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.triggers.utils.c.a(org.json.JSONArray):java.util.ArrayList");
    }
}

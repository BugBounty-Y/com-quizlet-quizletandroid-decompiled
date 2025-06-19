package com.facebook.appevents.suggestedevents;

import android.os.Bundle;
import android.util.Patterns;
import com.facebook.appevents.j;
import com.facebook.appevents.p;
import com.facebook.internal.J;
import com.facebook.o;
import com.facebook.t;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.regex.Pattern;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();
    public static Object b;
    public static Object c;
    public static Object d;
    public static JSONObject e;
    public static boolean f;

    public static final boolean a(String pathID, String str) {
        HashSet hashSet = f.e;
        b bVar = b.a;
        String str2 = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            try {
                Intrinsics.checkNotNullParameter(pathID, "pathID");
                LinkedHashMap linkedHashMap = b.b;
                if (linkedHashMap.containsKey(pathID)) {
                    str2 = (String) linkedHashMap.get(pathID);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(b.class, th);
            }
        }
        if (str2 == null) {
            return false;
        }
        if (!str2.equals("other")) {
            J.M(new androidx.credentials.playservices.controllers.c(23, str2, str));
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0081 A[Catch: all -> 0x005e, Exception -> 0x0088, TRY_LEAVE, TryCatch #5 {Exception -> 0x0088, blocks: (B:15:0x0045, B:16:0x0051, B:26:0x0068, B:27:0x006e, B:31:0x0079, B:32:0x007d, B:33:0x0081), top: B:55:0x0045 }] */
    /* JADX WARN: Removed duplicated region for block: B:47:0x008f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void b(android.view.View r6, android.view.View r7, java.lang.String r8) {
        /*
            java.lang.String r0 = "hostView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = "rootView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r0 = "activityName"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            int r0 = r6.hashCode()
            java.util.HashSet r1 = com.facebook.appevents.suggestedevents.f.e
            java.lang.Class<com.facebook.appevents.suggestedevents.f> r1 = com.facebook.appevents.suggestedevents.f.class
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r3 = 0
            if (r2 == 0) goto L20
        L1e:
            r2 = r3
            goto L28
        L20:
            java.util.HashSet r2 = com.facebook.appevents.suggestedevents.f.e     // Catch: java.lang.Throwable -> L23
            goto L28
        L23:
            r2 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r2)
            goto L1e
        L28:
            java.lang.Integer r4 = java.lang.Integer.valueOf(r0)
            boolean r2 = r2.contains(r4)
            if (r2 != 0) goto L9d
            com.facebook.appevents.suggestedevents.f r2 = new com.facebook.appevents.suggestedevents.f
            r2.<init>(r6, r7, r8)
            java.lang.Class<com.facebook.appevents.codeless.internal.g> r7 = com.facebook.appevents.codeless.internal.g.class
            boolean r8 = com.facebook.internal.instrument.crashshield.a.b(r7)
            if (r8 == 0) goto L40
            goto L88
        L40:
            java.lang.String r8 = "view"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r8)     // Catch: java.lang.Throwable -> L5e
            java.lang.String r8 = "android.view.View"
            java.lang.Class r8 = java.lang.Class.forName(r8)     // Catch: java.lang.Throwable -> L5e java.lang.Throwable -> L60 java.lang.Exception -> L88
            java.lang.String r4 = "mListenerInfo"
            java.lang.reflect.Field r8 = r8.getDeclaredField(r4)     // Catch: java.lang.Throwable -> L5e java.lang.Throwable -> L60 java.lang.Exception -> L88
            java.lang.String r4 = "android.view.View$ListenerInfo"
            java.lang.Class r4 = java.lang.Class.forName(r4)     // Catch: java.lang.Throwable -> L5e java.lang.Throwable -> L61 java.lang.Exception -> L88
            java.lang.String r5 = "mOnClickListener"
            java.lang.reflect.Field r4 = r4.getDeclaredField(r5)     // Catch: java.lang.Throwable -> L5e java.lang.Throwable -> L61 java.lang.Exception -> L88
            goto L62
        L5e:
            r6 = move-exception
            goto L85
        L60:
            r8 = r3
        L61:
            r4 = r3
        L62:
            if (r8 == 0) goto L81
            if (r4 != 0) goto L67
            goto L81
        L67:
            r5 = 1
            r8.setAccessible(r5)     // Catch: java.lang.Throwable -> L5e java.lang.Exception -> L88
            r4.setAccessible(r5)     // Catch: java.lang.Throwable -> L5e java.lang.Exception -> L88
            r8.setAccessible(r5)     // Catch: java.lang.Throwable -> L5e java.lang.IllegalAccessException -> L76 java.lang.Exception -> L88
            java.lang.Object r8 = r8.get(r6)     // Catch: java.lang.Throwable -> L5e java.lang.IllegalAccessException -> L76 java.lang.Exception -> L88
            goto L77
        L76:
            r8 = r3
        L77:
            if (r8 != 0) goto L7d
            r6.setOnClickListener(r2)     // Catch: java.lang.Throwable -> L5e java.lang.Exception -> L88
            goto L88
        L7d:
            r4.set(r8, r2)     // Catch: java.lang.Throwable -> L5e java.lang.Exception -> L88
            goto L88
        L81:
            r6.setOnClickListener(r2)     // Catch: java.lang.Throwable -> L5e java.lang.Exception -> L88
            goto L88
        L85:
            com.facebook.internal.instrument.crashshield.a.a(r7, r6)
        L88:
            boolean r6 = com.facebook.internal.instrument.crashshield.a.b(r1)
            if (r6 == 0) goto L8f
            goto L96
        L8f:
            java.util.HashSet r3 = com.facebook.appevents.suggestedevents.f.e     // Catch: java.lang.Throwable -> L92
            goto L96
        L92:
            r6 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r6)
        L96:
            java.lang.Integer r6 = java.lang.Integer.valueOf(r0)
            r3.add(r6)
        L9d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.suggestedevents.a.b(android.view.View, android.view.View, java.lang.String):void");
    }

    public static final float[] c(String appName, JSONObject viewHierarchy) {
        String lowerCase;
        JSONObject jSONObject;
        String screenName;
        JSONArray jSONArray;
        a aVar;
        JSONObject jSONObjectD;
        if (!com.facebook.internal.instrument.crashshield.a.b(a.class)) {
            try {
                Intrinsics.checkNotNullParameter(viewHierarchy, "viewHierarchy");
                Intrinsics.checkNotNullParameter(appName, "appName");
                if (f) {
                    float[] fArr = new float[30];
                    for (int i = 0; i < 30; i++) {
                        fArr[i] = 0.0f;
                    }
                    try {
                        lowerCase = appName.toLowerCase();
                        Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
                        jSONObject = new JSONObject(viewHierarchy.optJSONObject("view").toString());
                        screenName = viewHierarchy.optString("screenname");
                        jSONArray = new JSONArray();
                        aVar = a;
                        aVar.k(jSONArray, jSONObject);
                        aVar.n(fArr, aVar.i(jSONObject));
                        jSONObjectD = aVar.d(jSONObject);
                    } catch (JSONException unused) {
                    }
                    if (jSONObjectD != null) {
                        Intrinsics.checkNotNullExpressionValue(screenName, "screenName");
                        String string = jSONObject.toString();
                        Intrinsics.checkNotNullExpressionValue(string, "viewTree.toString()");
                        aVar.n(fArr, aVar.h(jSONObjectD, jSONArray, screenName, string, lowerCase));
                        return fArr;
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(a.class, th);
                return null;
            }
        }
        return null;
    }

    public static final String e(String buttonText, String activityName, String appName) {
        if (com.facebook.internal.instrument.crashshield.a.b(a.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(buttonText, "buttonText");
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            Intrinsics.checkNotNullParameter(appName, "appName");
            String lowerCase = (appName + " | " + activityName + ", " + buttonText).toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
            return lowerCase;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(a.class, th);
            return null;
        }
    }

    public static final void f(File file) {
        if (com.facebook.internal.instrument.crashshield.a.b(a.class)) {
            return;
        }
        try {
            try {
                e = new JSONObject();
                FileInputStream fileInputStream = new FileInputStream(file);
                byte[] bArr = new byte[fileInputStream.available()];
                fileInputStream.read(bArr);
                fileInputStream.close();
                e = new JSONObject(new String(bArr, Charsets.UTF_8));
                b = V.f(new Pair("ENGLISH", "1"), new Pair("GERMAN", "2"), new Pair("SPANISH", "3"), new Pair("JAPANESE", "4"));
                c = V.f(new Pair("VIEW_CONTENT", "0"), new Pair("SEARCH", "1"), new Pair("ADD_TO_CART", "2"), new Pair("ADD_TO_WISHLIST", "3"), new Pair("INITIATE_CHECKOUT", "4"), new Pair("ADD_PAYMENT_INFO", "5"), new Pair("PURCHASE", "6"), new Pair("LEAD", "7"), new Pair("COMPLETE_REGISTRATION", "8"));
                d = V.f(new Pair("BUTTON_TEXT", "1"), new Pair("PAGE_TITLE", "2"), new Pair("RESOLVED_DOCUMENT_LINK", "3"), new Pair("BUTTON_ID", "4"));
                f = true;
            } catch (Exception unused) {
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(a.class, th);
        }
    }

    public static void j(String event, String str, float[] fArr) throws Throwable {
        boolean zContains;
        boolean zContains2;
        d dVar = d.a;
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            zContains = false;
        } else {
            try {
                Intrinsics.checkNotNullParameter(event, "event");
                zContains = d.c.contains(event);
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(d.class, th);
            }
        }
        if (zContains) {
            j jVar = new p(o.a()).a;
            jVar.getClass();
            if (com.facebook.internal.instrument.crashshield.a.b(jVar)) {
                return;
            }
            try {
                Bundle bundle = new Bundle();
                bundle.putString("_is_suggested_event", "1");
                bundle.putString("_button_text", str);
                jVar.d(bundle, event);
                return;
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(jVar, th2);
                return;
            }
        }
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            zContains2 = false;
        } else {
            try {
                Intrinsics.checkNotNullParameter(event, "event");
                zContains2 = d.d.contains(event);
            } catch (Throwable th3) {
                com.facebook.internal.instrument.crashshield.a.a(d.class, th3);
            }
        }
        if (zContains2) {
            Bundle bundle2 = new Bundle();
            try {
                bundle2.putString("event_name", event);
                JSONObject jSONObject = new JSONObject();
                StringBuilder sb = new StringBuilder();
                for (float f2 : fArr) {
                    sb.append(f2);
                    sb.append(",");
                }
                jSONObject.put("dense", sb.toString());
                jSONObject.put("button_text", str);
                bundle2.putString("metadata", jSONObject.toString());
                String str2 = t.j;
                String str3 = String.format(Locale.US, "%s/suggested_events", Arrays.copyOf(new Object[]{o.b()}, 1));
                Intrinsics.checkNotNullExpressionValue(str3, "format(locale, format, *args)");
                t tVarR = assistantMode.utils.studiableMetadata.b.R(null, str3, null, null);
                Intrinsics.checkNotNullParameter(bundle2, "<set-?>");
                tVarR.d = bundle2;
                tVarR.c();
            } catch (JSONException unused) {
            }
        }
    }

    public JSONObject d(JSONObject jSONObject) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
        } catch (JSONException unused) {
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
        if (jSONObject.optBoolean("is_interacted")) {
            return jSONObject;
        }
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("childviews");
        if (jSONArrayOptJSONArray == null) {
            return null;
        }
        int length = jSONArrayOptJSONArray.length();
        for (int i = 0; i < length; i++) {
            JSONObject jSONObject2 = jSONArrayOptJSONArray.getJSONObject(i);
            Intrinsics.checkNotNullExpressionValue(jSONObject2, "children.getJSONObject(i)");
            JSONObject jSONObjectD = d(jSONObject2);
            if (jSONObjectD != null) {
                return jSONObjectD;
            }
        }
        return null;
    }

    public boolean g(String[] strArr, String[] strArr2) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                for (String str : strArr) {
                    for (String str2 : strArr2) {
                        if (StringsKt.G(str2, str, false)) {
                            return true;
                        }
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return false;
            }
        }
        return false;
    }

    public float[] h(JSONObject jSONObject, JSONArray jSONArray, String str, String str2, String str3) {
        float[] fArr;
        float f2;
        float[] fArr2 = null;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            float[] fArr3 = new float[30];
            int i = 0;
            while (true) {
                f2 = DefinitionKt.NO_Float_VALUE;
                if (i >= 30) {
                    break;
                }
                fArr3[i] = 0.0f;
                i++;
            }
            int length = jSONArray.length();
            boolean z = true;
            fArr3[3] = length > 1 ? length - 1.0f : 0.0f;
            try {
                int length2 = jSONArray.length();
                int i2 = 0;
                while (i2 < length2) {
                    fArr = fArr2;
                    try {
                        try {
                            JSONObject jSONObject2 = jSONArray.getJSONObject(i2);
                            boolean z2 = z;
                            Intrinsics.checkNotNullExpressionValue(jSONObject2, "siblings.getJSONObject(i)");
                            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                                try {
                                    if (((jSONObject2.optInt("classtypebitmask") & 1) << 5) > 0) {
                                        fArr3[9] = fArr3[9] + 1.0f;
                                    }
                                } catch (Throwable th) {
                                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                                }
                            }
                            i2++;
                            fArr2 = fArr;
                            z = z2;
                        } catch (JSONException unused) {
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        com.facebook.internal.instrument.crashshield.a.a(this, th);
                        return fArr;
                    }
                }
            } catch (JSONException unused2) {
            }
            fArr = fArr2;
            fArr3[13] = -1.0f;
            fArr3[14] = -1.0f;
            String str4 = str + '|' + str3;
            StringBuilder sb = new StringBuilder();
            StringBuilder sb2 = new StringBuilder();
            o(jSONObject, sb2, sb);
            String string = sb.toString();
            Intrinsics.checkNotNullExpressionValue(string, "hintSB.toString()");
            String string2 = sb2.toString();
            Intrinsics.checkNotNullExpressionValue(string2, "textSB.toString()");
            fArr3[15] = m("COMPLETE_REGISTRATION", "BUTTON_TEXT", string2) ? 1.0f : 0.0f;
            fArr3[16] = m("COMPLETE_REGISTRATION", "PAGE_TITLE", str4) ? 1.0f : 0.0f;
            fArr3[17] = m("COMPLETE_REGISTRATION", "BUTTON_ID", string) ? 1.0f : 0.0f;
            fArr3[18] = StringsKt.G(str2, DBStudySetFields.Names.PASSWORD, false) ? 1.0f : 0.0f;
            fArr3[19] = l("(?i)(confirm.*password)|(password.*(confirmation|confirm)|confirmation)", str2) ? 1.0f : 0.0f;
            fArr3[20] = l("(?i)(sign in)|login|signIn", str2) ? 1.0f : 0.0f;
            fArr3[21] = l("(?i)(sign.*(up|now)|registration|register|(create|apply).*(profile|account)|open.*account|account.*(open|creation|application)|enroll|join.*now)", str2) ? 1.0f : 0.0f;
            fArr3[22] = m("PURCHASE", "BUTTON_TEXT", string2) ? 1.0f : 0.0f;
            fArr3[24] = m("PURCHASE", "PAGE_TITLE", str4) ? 1.0f : 0.0f;
            fArr3[25] = l("(?i)add to(\\s|\\Z)|update(\\s|\\Z)|cart", string2) ? 1.0f : 0.0f;
            fArr3[27] = l("(?i)add to(\\s|\\Z)|update(\\s|\\Z)|cart|shop|buy", str4) ? 1.0f : 0.0f;
            fArr3[28] = m("LEAD", "BUTTON_TEXT", string2) ? 1.0f : 0.0f;
            if (m("LEAD", "PAGE_TITLE", str4)) {
                f2 = 1.0f;
            }
            fArr3[29] = f2;
            return fArr3;
        } catch (Throwable th3) {
            th = th3;
            fArr = null;
        }
    }

    public float[] i(JSONObject jSONObject) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            float[] fArr = new float[30];
            for (int i = 0; i < 30; i++) {
                fArr[i] = 0.0f;
            }
            String strOptString = jSONObject.optString("text");
            Intrinsics.checkNotNullExpressionValue(strOptString, "node.optString(TEXT_KEY)");
            String lowerCase = strOptString.toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
            String strOptString2 = jSONObject.optString("hint");
            Intrinsics.checkNotNullExpressionValue(strOptString2, "node.optString(HINT_KEY)");
            String lowerCase2 = strOptString2.toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase2, "this as java.lang.String).toLowerCase()");
            String strOptString3 = jSONObject.optString("classname");
            Intrinsics.checkNotNullExpressionValue(strOptString3, "node.optString(CLASS_NAME_KEY)");
            String lowerCase3 = strOptString3.toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase3, "this as java.lang.String).toLowerCase()");
            int iOptInt = jSONObject.optInt("inputtype", -1);
            String[] strArr = {lowerCase, lowerCase2};
            if (g(new String[]{"$", "amount", "price", "total"}, strArr)) {
                fArr[0] = fArr[0] + 1.0f;
            }
            if (g(new String[]{DBStudySetFields.Names.PASSWORD, "pwd"}, strArr)) {
                fArr[1] = fArr[1] + 1.0f;
            }
            if (g(new String[]{"tel", "phone"}, strArr)) {
                fArr[2] = fArr[2] + 1.0f;
            }
            if (g(new String[]{"search"}, strArr)) {
                fArr[4] = fArr[4] + 1.0f;
            }
            if (iOptInt >= 0) {
                fArr[5] = fArr[5] + 1.0f;
            }
            if (iOptInt == 2 || iOptInt == 3) {
                fArr[6] = fArr[6] + 1.0f;
            }
            if (iOptInt == 32 || Patterns.EMAIL_ADDRESS.matcher(lowerCase).matches()) {
                fArr[7] = fArr[7] + 1.0f;
            }
            if (StringsKt.G(lowerCase3, "checkbox", false)) {
                fArr[8] = fArr[8] + 1.0f;
            }
            if (g(new String[]{"complete", "confirm", "done", "submit"}, new String[]{lowerCase})) {
                fArr[10] = fArr[10] + 1.0f;
            }
            if (StringsKt.G(lowerCase3, "radio", false) && StringsKt.G(lowerCase3, "button", false)) {
                fArr[12] = fArr[12] + 1.0f;
            }
            try {
                JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("childviews");
                int length = jSONArrayOptJSONArray.length();
                for (int i2 = 0; i2 < length; i2++) {
                    JSONObject jSONObject2 = jSONArrayOptJSONArray.getJSONObject(i2);
                    Intrinsics.checkNotNullExpressionValue(jSONObject2, "childViews.getJSONObject(i)");
                    n(fArr, i(jSONObject2));
                }
            } catch (JSONException unused) {
            }
            return fArr;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public boolean k(JSONArray jSONArray, JSONObject jSONObject) {
        boolean z;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                if (jSONObject.optBoolean("is_interacted")) {
                    return true;
                }
                JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("childviews");
                int length = jSONArrayOptJSONArray.length();
                int i = 0;
                while (true) {
                    if (i >= length) {
                        z = false;
                        break;
                    }
                    if (jSONArrayOptJSONArray.getJSONObject(i).optBoolean("is_interacted")) {
                        z = true;
                        break;
                    }
                    i++;
                }
                boolean z2 = z;
                JSONArray jSONArray2 = new JSONArray();
                if (z) {
                    int length2 = jSONArrayOptJSONArray.length();
                    for (int i2 = 0; i2 < length2; i2++) {
                        jSONArray.put(jSONArrayOptJSONArray.getJSONObject(i2));
                    }
                    return z2;
                }
                int length3 = jSONArrayOptJSONArray.length();
                for (int i3 = 0; i3 < length3; i3++) {
                    JSONObject child = jSONArrayOptJSONArray.getJSONObject(i3);
                    Intrinsics.checkNotNullExpressionValue(child, "child");
                    if (k(jSONArray, child)) {
                        jSONArray2.put(child);
                        z2 = true;
                    }
                }
                jSONObject.put("childviews", jSONArray2);
                return z2;
            } catch (JSONException unused) {
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        }
        return false;
    }

    public boolean l(String str, String str2) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return false;
        }
        try {
            return Pattern.compile(str).matcher(str2).find();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return false;
        }
    }

    /* JADX WARN: Type inference failed for: r0v6, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v1, types: [java.lang.Object, java.util.Map] */
    public boolean m(String str, String str2, String str3) {
        JSONObject jSONObjectOptJSONObject;
        JSONObject jSONObjectOptJSONObject2;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                JSONObject jSONObject = e;
                String strOptString = null;
                if (jSONObject == null) {
                    Intrinsics.m("rules");
                    throw null;
                }
                JSONObject jSONObjectOptJSONObject3 = jSONObject.optJSONObject("rulesForLanguage");
                if (jSONObjectOptJSONObject3 != null) {
                    ?? r4 = b;
                    if (r4 == 0) {
                        Intrinsics.m("languageInfo");
                        throw null;
                    }
                    JSONObject jSONObjectOptJSONObject4 = jSONObjectOptJSONObject3.optJSONObject((String) r4.get("ENGLISH"));
                    if (jSONObjectOptJSONObject4 != null && (jSONObjectOptJSONObject = jSONObjectOptJSONObject4.optJSONObject("rulesForEvent")) != null) {
                        ?? r1 = c;
                        if (r1 == 0) {
                            Intrinsics.m("eventInfo");
                            throw null;
                        }
                        JSONObject jSONObjectOptJSONObject5 = jSONObjectOptJSONObject.optJSONObject((String) r1.get(str));
                        if (jSONObjectOptJSONObject5 != null && (jSONObjectOptJSONObject2 = jSONObjectOptJSONObject5.optJSONObject("positiveRules")) != null) {
                            ?? r0 = d;
                            if (r0 == 0) {
                                Intrinsics.m("textTypeInfo");
                                throw null;
                            }
                            strOptString = jSONObjectOptJSONObject2.optString((String) r0.get(str2));
                        }
                    }
                }
                if (strOptString != null) {
                    return l(strOptString, str3);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return false;
            }
        }
        return false;
    }

    public void n(float[] fArr, float[] fArr2) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            int length = fArr.length;
            for (int i = 0; i < length; i++) {
                fArr[i] = fArr[i] + fArr2[i];
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public void o(JSONObject jSONObject, StringBuilder sb, StringBuilder sb2) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            String strOptString = jSONObject.optString("text", "");
            Intrinsics.checkNotNullExpressionValue(strOptString, "view.optString(TEXT_KEY, \"\")");
            String lowerCase = strOptString.toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
            String strOptString2 = jSONObject.optString("hint", "");
            Intrinsics.checkNotNullExpressionValue(strOptString2, "view.optString(HINT_KEY, \"\")");
            String lowerCase2 = strOptString2.toLowerCase();
            Intrinsics.checkNotNullExpressionValue(lowerCase2, "this as java.lang.String).toLowerCase()");
            if (lowerCase.length() > 0) {
                sb.append(lowerCase);
                sb.append(" ");
            }
            if (lowerCase2.length() > 0) {
                sb2.append(lowerCase2);
                sb2.append(" ");
            }
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("childviews");
            if (jSONArrayOptJSONArray == null) {
                return;
            }
            int length = jSONArrayOptJSONArray.length();
            for (int i = 0; i < length; i++) {
                try {
                    JSONObject currentChildView = jSONArrayOptJSONArray.getJSONObject(i);
                    Intrinsics.checkNotNullExpressionValue(currentChildView, "currentChildView");
                    o(currentChildView, sb, sb2);
                } catch (JSONException unused) {
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}

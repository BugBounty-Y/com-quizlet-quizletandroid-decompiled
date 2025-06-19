package com.facebook.appevents.iap;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class o {
    public static final o a = new o();
    public static final HashMap b = new HashMap();
    public static final HashMap c = new HashMap();
    public static final String d = com.facebook.o.a().getPackageName();
    public static final SharedPreferences e = com.facebook.o.a().getSharedPreferences("com.facebook.internal.SKU_DETAILS", 0);
    public static final SharedPreferences f = com.facebook.o.a().getSharedPreferences("com.facebook.internal.PURCHASE", 0);

    public static final ArrayList f(Context context, Object obj) {
        if (com.facebook.internal.instrument.crashshield.a.b(o.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(context, "context");
            o oVar = a;
            return oVar.a(oVar.e(context, obj, "inapp"));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(o.class, th);
            return null;
        }
    }

    public final ArrayList a(ArrayList arrayList) {
        SharedPreferences sharedPreferences = f;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            ArrayList arrayList2 = new ArrayList();
            SharedPreferences.Editor editorEdit = sharedPreferences.edit();
            long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                String str = (String) it2.next();
                try {
                    JSONObject jSONObject = new JSONObject(str);
                    String string = jSONObject.getString("productId");
                    long j = jSONObject.getLong("purchaseTime");
                    String string2 = jSONObject.getString("purchaseToken");
                    if (jCurrentTimeMillis - (j / 1000) <= 86400 && !Intrinsics.b(sharedPreferences.getString(string, ""), string2)) {
                        editorEdit.putString(string, string2);
                        arrayList2.add(str);
                    }
                } catch (JSONException unused) {
                }
            }
            editorEdit.apply();
            return arrayList2;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final Class b(Context context, String className) {
        Class<?> clsLoadClass;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        HashMap map = c;
        try {
            Class cls = (Class) map.get(className);
            if (cls != null) {
                return cls;
            }
            if (com.facebook.internal.instrument.crashshield.a.b(u.class)) {
                clsLoadClass = null;
            } else {
                try {
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intrinsics.checkNotNullParameter(className, "className");
                    try {
                        clsLoadClass = context.getClassLoader().loadClass(className);
                    } catch (ClassNotFoundException unused) {
                    }
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(u.class, th);
                }
            }
            if (clsLoadClass != null) {
                map.put(className, clsLoadClass);
            }
            return clsLoadClass;
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
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
    /* JADX WARN: Removed duplicated region for block: B:32:0x0070  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.reflect.Method c(java.lang.Class r8, java.lang.String r9) {
        /*
            r7 = this;
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r7)
            r1 = 0
            if (r0 == 0) goto L8
            return r1
        L8:
            java.util.HashMap r0 = com.facebook.appevents.iap.o.b     // Catch: java.lang.Throwable -> L34
            java.lang.Object r2 = r0.get(r9)     // Catch: java.lang.Throwable -> L34
            java.lang.reflect.Method r2 = (java.lang.reflect.Method) r2     // Catch: java.lang.Throwable -> L34
            if (r2 == 0) goto L13
            return r2
        L13:
            int r2 = r9.hashCode()     // Catch: java.lang.Throwable -> L34
            java.lang.Class<android.os.Bundle> r3 = android.os.Bundle.class
            java.lang.String r4 = "TYPE"
            java.lang.Class r5 = java.lang.Integer.TYPE
            java.lang.Class<java.lang.String> r6 = java.lang.String.class
            switch(r2) {
                case -1801122596: goto L68;
                case -1450694211: goto L57;
                case -1123215065: goto L47;
                case -594356707: goto L36;
                case -573310373: goto L23;
                default: goto L22;
            }
        L22:
            goto L70
        L23:
            java.lang.String r2 = "getSkuDetails"
            boolean r2 = r9.equals(r2)     // Catch: java.lang.Throwable -> L34
            if (r2 != 0) goto L2c
            goto L70
        L2c:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r4)     // Catch: java.lang.Throwable -> L34
            java.lang.Class[] r2 = new java.lang.Class[]{r5, r6, r6, r3}     // Catch: java.lang.Throwable -> L34
            goto L79
        L34:
            r8 = move-exception
            goto L95
        L36:
            java.lang.String r2 = "getPurchaseHistory"
            boolean r2 = r9.equals(r2)     // Catch: java.lang.Throwable -> L34
            if (r2 != 0) goto L3f
            goto L70
        L3f:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r4)     // Catch: java.lang.Throwable -> L34
            java.lang.Class[] r2 = new java.lang.Class[]{r5, r6, r6, r6, r3}     // Catch: java.lang.Throwable -> L34
            goto L79
        L47:
            java.lang.String r2 = "asInterface"
            boolean r2 = r9.equals(r2)     // Catch: java.lang.Throwable -> L34
            if (r2 != 0) goto L50
            goto L70
        L50:
            java.lang.Class<android.os.IBinder> r2 = android.os.IBinder.class
            java.lang.Class[] r2 = new java.lang.Class[]{r2}     // Catch: java.lang.Throwable -> L34
            goto L79
        L57:
            java.lang.String r2 = "isBillingSupported"
            boolean r2 = r9.equals(r2)     // Catch: java.lang.Throwable -> L34
            if (r2 != 0) goto L60
            goto L70
        L60:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r4)     // Catch: java.lang.Throwable -> L34
            java.lang.Class[] r2 = new java.lang.Class[]{r5, r6, r6}     // Catch: java.lang.Throwable -> L34
            goto L79
        L68:
            java.lang.String r2 = "getPurchases"
            boolean r2 = r9.equals(r2)     // Catch: java.lang.Throwable -> L34
            if (r2 != 0) goto L72
        L70:
            r2 = r1
            goto L79
        L72:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r4)     // Catch: java.lang.Throwable -> L34
            java.lang.Class[] r2 = new java.lang.Class[]{r5, r6, r6, r6}     // Catch: java.lang.Throwable -> L34
        L79:
            if (r2 != 0) goto L84
            java.lang.Class[] r2 = new java.lang.Class[]{r1}     // Catch: java.lang.Throwable -> L34
            java.lang.reflect.Method r8 = com.facebook.appevents.iap.u.f(r8, r9, r2)     // Catch: java.lang.Throwable -> L34
            goto L8f
        L84:
            int r3 = r2.length     // Catch: java.lang.Throwable -> L34
            java.lang.Object[] r2 = java.util.Arrays.copyOf(r2, r3)     // Catch: java.lang.Throwable -> L34
            java.lang.Class[] r2 = (java.lang.Class[]) r2     // Catch: java.lang.Throwable -> L34
            java.lang.reflect.Method r8 = com.facebook.appevents.iap.u.f(r8, r9, r2)     // Catch: java.lang.Throwable -> L34
        L8f:
            if (r8 == 0) goto L94
            r0.put(r9, r8)     // Catch: java.lang.Throwable -> L34
        L94:
            return r8
        L95:
            com.facebook.internal.instrument.crashshield.a.a(r7, r8)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.o.c(java.lang.Class, java.lang.String):java.lang.reflect.Method");
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0089  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.ArrayList d(android.content.Context r18, java.lang.Object r19) {
        /*
            r17 = this;
            r1 = r17
            java.lang.String r0 = "inapp"
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r7 = 0
            if (r2 == 0) goto Lc
            return r7
        Lc:
            java.util.ArrayList r8 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L7f
            r8.<init>()     // Catch: java.lang.Throwable -> L7f
            r2 = r18
            r5 = r19
            boolean r3 = r1.i(r2, r5, r0)     // Catch: java.lang.Throwable -> L7f
            if (r3 == 0) goto L98
            r3 = 0
            r9 = r3
            r10 = r9
            r3 = r7
        L1f:
            r4 = 6
            java.lang.Integer r4 = java.lang.Integer.valueOf(r4)     // Catch: java.lang.Throwable -> L7f
            java.lang.String r6 = com.facebook.appevents.iap.o.d     // Catch: java.lang.Throwable -> L7f
            android.os.Bundle r11 = new android.os.Bundle     // Catch: java.lang.Throwable -> L7f
            r11.<init>()     // Catch: java.lang.Throwable -> L7f
            java.lang.Object[] r6 = new java.lang.Object[]{r4, r6, r0, r3, r11}     // Catch: java.lang.Throwable -> L7f
            java.lang.String r3 = "com.android.vending.billing.IInAppBillingService"
            java.lang.String r4 = "getPurchaseHistory"
            java.lang.Object r3 = r1.h(r2, r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L7f
            if (r3 == 0) goto L89
            long r4 = java.lang.System.currentTimeMillis()     // Catch: java.lang.Throwable -> L7f
            r11 = 1000(0x3e8, double:4.94E-321)
            long r4 = r4 / r11
            android.os.Bundle r3 = (android.os.Bundle) r3     // Catch: java.lang.Throwable -> L7f
            java.lang.String r2 = "RESPONSE_CODE"
            int r2 = r3.getInt(r2)     // Catch: java.lang.Throwable -> L7f
            if (r2 != 0) goto L89
            java.lang.String r2 = "INAPP_PURCHASE_DATA_LIST"
            java.util.ArrayList r2 = r3.getStringArrayList(r2)     // Catch: java.lang.Throwable -> L7f
            if (r2 != 0) goto L53
            goto L89
        L53:
            java.util.Iterator r2 = r2.iterator()     // Catch: java.lang.Throwable -> L7f
        L57:
            boolean r6 = r2.hasNext()     // Catch: java.lang.Throwable -> L7f
            if (r6 == 0) goto L81
            java.lang.Object r6 = r2.next()     // Catch: java.lang.Throwable -> L7f
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Throwable -> L7f
            org.json.JSONObject r13 = new org.json.JSONObject     // Catch: org.json.JSONException -> L57 java.lang.Throwable -> L7f
            r13.<init>(r6)     // Catch: org.json.JSONException -> L57 java.lang.Throwable -> L7f
            java.lang.String r14 = "purchaseTime"
            long r13 = r13.getLong(r14)     // Catch: org.json.JSONException -> L57 java.lang.Throwable -> L7f
            long r13 = r13 / r11
            long r13 = r4 - r13
            r15 = 1200(0x4b0, double:5.93E-321)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 <= 0) goto L79
            r10 = 1
            goto L81
        L79:
            r8.add(r6)     // Catch: org.json.JSONException -> L57 java.lang.Throwable -> L7f
            int r9 = r9 + 1
            goto L57
        L7f:
            r0 = move-exception
            goto L99
        L81:
            java.lang.String r2 = "INAPP_CONTINUATION_TOKEN"
            java.lang.String r2 = r3.getString(r2)     // Catch: java.lang.Throwable -> L7f
            r3 = r2
            goto L8a
        L89:
            r3 = r7
        L8a:
            r2 = 30
            if (r9 >= r2) goto L98
            if (r3 == 0) goto L98
            if (r10 == 0) goto L93
            goto L98
        L93:
            r2 = r18
            r5 = r19
            goto L1f
        L98:
            return r8
        L99:
            com.facebook.internal.instrument.crashshield.a.a(r1, r0)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.o.d(android.content.Context, java.lang.Object):java.util.ArrayList");
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0056  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.ArrayList e(android.content.Context r13, java.lang.Object r14, java.lang.String r15) {
        /*
            r12 = this;
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r12)
            r1 = 0
            if (r0 == 0) goto L8
            return r1
        L8:
            java.util.ArrayList r0 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L61
            r0.<init>()     // Catch: java.lang.Throwable -> L61
            if (r14 != 0) goto L11
        Lf:
            r6 = r12
            goto L64
        L11:
            boolean r2 = r12.i(r13, r14, r15)     // Catch: java.lang.Throwable -> L61
            if (r2 == 0) goto Lf
            r2 = 0
            r3 = r1
        L19:
            r4 = 3
            java.lang.Integer r4 = java.lang.Integer.valueOf(r4)     // Catch: java.lang.Throwable -> L61
            java.lang.String r5 = com.facebook.appevents.iap.o.d     // Catch: java.lang.Throwable -> L61
            java.lang.Object[] r11 = new java.lang.Object[]{r4, r5, r15, r3}     // Catch: java.lang.Throwable -> L61
            java.lang.String r8 = "com.android.vending.billing.IInAppBillingService"
            java.lang.String r9 = "getPurchases"
            r6 = r12
            r7 = r13
            r10 = r14
            java.lang.Object r13 = r6.h(r7, r8, r9, r10, r11)     // Catch: java.lang.Throwable -> L53
            if (r13 == 0) goto L56
            android.os.Bundle r13 = (android.os.Bundle) r13     // Catch: java.lang.Throwable -> L53
            java.lang.String r14 = "RESPONSE_CODE"
            int r14 = r13.getInt(r14)     // Catch: java.lang.Throwable -> L53
            if (r14 != 0) goto L56
            java.lang.String r14 = "INAPP_PURCHASE_DATA_LIST"
            java.util.ArrayList r14 = r13.getStringArrayList(r14)     // Catch: java.lang.Throwable -> L53
            if (r14 == 0) goto L64
            int r3 = r14.size()     // Catch: java.lang.Throwable -> L53
            int r2 = r2 + r3
            r0.addAll(r14)     // Catch: java.lang.Throwable -> L53
            java.lang.String r14 = "INAPP_CONTINUATION_TOKEN"
            java.lang.String r13 = r13.getString(r14)     // Catch: java.lang.Throwable -> L53
            r3 = r13
            goto L57
        L53:
            r0 = move-exception
        L54:
            r13 = r0
            goto L65
        L56:
            r3 = r1
        L57:
            r13 = 30
            if (r2 >= r13) goto L64
            if (r3 != 0) goto L5e
            goto L64
        L5e:
            r13 = r7
            r14 = r10
            goto L19
        L61:
            r0 = move-exception
            r6 = r12
            goto L54
        L64:
            return r0
        L65:
            com.facebook.internal.instrument.crashshield.a.a(r12, r13)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.o.e(android.content.Context, java.lang.Object, java.lang.String):java.util.ArrayList");
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    public final LinkedHashMap g(Context context, ArrayList arrayList, Object obj, boolean z) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            if (obj != null && !arrayList.isEmpty()) {
                Bundle bundle = new Bundle();
                bundle.putStringArrayList("ITEM_ID_LIST", arrayList);
                try {
                    Object objH = h(context, "com.android.vending.billing.IInAppBillingService", "getSkuDetails", obj, new Object[]{3, d, z ? "subs" : "inapp", bundle});
                    if (objH != null) {
                        Bundle bundle2 = (Bundle) objH;
                        if (bundle2.getInt("RESPONSE_CODE") == 0) {
                            ArrayList<String> stringArrayList = bundle2.getStringArrayList("DETAILS_LIST");
                            if (stringArrayList != null && arrayList.size() == stringArrayList.size()) {
                                int size = arrayList.size();
                                for (int i = 0; i < size; i++) {
                                    Object obj2 = arrayList.get(i);
                                    Intrinsics.checkNotNullExpressionValue(obj2, "skuList[i]");
                                    String str = stringArrayList.get(i);
                                    Intrinsics.checkNotNullExpressionValue(str, "skuDetailsList[i]");
                                    linkedHashMap.put(obj2, str);
                                }
                            }
                            k(linkedHashMap);
                            return linkedHashMap;
                        }
                    }
                } catch (Throwable th) {
                    th = th;
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                    return null;
                }
            }
            return linkedHashMap;
        } catch (Throwable th2) {
            th = th2;
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final Object h(Context context, String str, String str2, Object obj, Object[] objArr) {
        Method methodC;
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Class clsB = b(context, str);
                if (clsB != null && (methodC = c(clsB, str2)) != null) {
                    return u.h(clsB, obj, methodC, Arrays.copyOf(objArr, objArr.length));
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final boolean i(Context context, Object obj, String str) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this) && obj != null) {
            try {
            } catch (Throwable th) {
                th = th;
            }
            try {
                Object objH = h(context, "com.android.vending.billing.IInAppBillingService", "isBillingSupported", obj, new Object[]{3, d, str});
                if (objH != null) {
                    if (((Integer) objH).intValue() == 0) {
                        return true;
                    }
                }
            } catch (Throwable th2) {
                th = th2;
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return false;
            }
        }
        return false;
    }

    public final LinkedHashMap j(ArrayList arrayList) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                String sku = (String) it2.next();
                String string = e.getString(sku, null);
                if (string != null) {
                    List listSplit$default = StringsKt__StringsKt.split$default(string, new String[]{";"}, false, 2, 2, null);
                    if (jCurrentTimeMillis - Long.parseLong((String) listSplit$default.get(0)) < 43200) {
                        Intrinsics.checkNotNullExpressionValue(sku, "sku");
                        linkedHashMap.put(sku, listSplit$default.get(1));
                    }
                }
            }
            return linkedHashMap;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final void k(LinkedHashMap linkedHashMap) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
            SharedPreferences.Editor editorEdit = e.edit();
            for (Map.Entry entry : linkedHashMap.entrySet()) {
                editorEdit.putString((String) entry.getKey(), jCurrentTimeMillis + ';' + ((String) entry.getValue()));
            }
            editorEdit.apply();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}

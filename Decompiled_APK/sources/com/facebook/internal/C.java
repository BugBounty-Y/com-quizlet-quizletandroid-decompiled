package com.facebook.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.facebook.login.EnumC1567d;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C {
    public static final C a;
    public static final ArrayList b;
    public static final AtomicBoolean c;
    public static final Integer[] d;

    static {
        C c2 = new C();
        a = c2;
        b = c2.a();
        ArrayList arrayList = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(c2)) {
            try {
                ArrayList arrayListF = kotlin.collections.B.f(new B(0));
                arrayListF.addAll(c2.a());
                arrayList = arrayListF;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(c2, th);
            }
        }
        C c3 = a;
        if (!com.facebook.internal.instrument.crashshield.a.b(c3)) {
            try {
                HashMap map = new HashMap();
                ArrayList arrayList2 = new ArrayList();
                arrayList2.add(new B(3));
                ArrayList arrayList3 = b;
                map.put("com.facebook.platform.action.request.OGACTIONPUBLISH_DIALOG", arrayList3);
                map.put("com.facebook.platform.action.request.FEED_DIALOG", arrayList3);
                map.put("com.facebook.platform.action.request.LIKE_DIALOG", arrayList3);
                map.put("com.facebook.platform.action.request.APPINVITES_DIALOG", arrayList3);
                map.put("com.facebook.platform.action.request.MESSAGE_DIALOG", arrayList2);
                map.put("com.facebook.platform.action.request.OGMESSAGEPUBLISH_DIALOG", arrayList2);
                map.put("com.facebook.platform.action.request.CAMERA_EFFECT", arrayList);
                map.put("com.facebook.platform.action.request.SHARE_STORY", arrayList3);
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(c3, th2);
            }
        }
        c = new AtomicBoolean(false);
        d = new Integer[]{20210906, 20171115, 20170417, 20170411, 20170213, 20161017, 20160327, 20150702, 20150401, 20141218, 20141107, 20141028, 20141001, 20140701, 20140324, 20140313, 20140204, 20131107, 20131024, 20130618, 20130502, 20121101};
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0050, code lost:
    
        if ((r3 % 2) != 0) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0056, code lost:
    
        return java.lang.Math.min(r4, r9);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int b(java.util.TreeSet r8, int r9, int[] r10) {
        /*
            java.lang.Class<com.facebook.internal.C> r0 = com.facebook.internal.C.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)
            r2 = 0
            if (r1 == 0) goto La
            return r2
        La:
            java.lang.String r1 = "versionSpec"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r1)     // Catch: java.lang.Throwable -> L41
            r1 = -1
            if (r8 != 0) goto L13
            goto L57
        L13:
            int r3 = r10.length     // Catch: java.lang.Throwable -> L41
            int r3 = r3 + (-1)
            java.util.Iterator r8 = r8.descendingIterator()     // Catch: java.lang.Throwable -> L41
            r4 = r1
        L1b:
            boolean r5 = r8.hasNext()     // Catch: java.lang.Throwable -> L41
            if (r5 == 0) goto L57
            java.lang.Object r5 = r8.next()     // Catch: java.lang.Throwable -> L41
            java.lang.Integer r5 = (java.lang.Integer) r5     // Catch: java.lang.Throwable -> L41
            java.lang.String r6 = "fbAppVersion"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)     // Catch: java.lang.Throwable -> L41
            int r6 = r5.intValue()     // Catch: java.lang.Throwable -> L41
            int r4 = java.lang.Math.max(r4, r6)     // Catch: java.lang.Throwable -> L41
        L34:
            if (r3 < 0) goto L43
            r6 = r10[r3]     // Catch: java.lang.Throwable -> L41
            int r7 = r5.intValue()     // Catch: java.lang.Throwable -> L41
            if (r6 <= r7) goto L43
            int r3 = r3 + (-1)
            goto L34
        L41:
            r8 = move-exception
            goto L58
        L43:
            if (r3 >= 0) goto L46
            goto L57
        L46:
            r6 = r10[r3]     // Catch: java.lang.Throwable -> L41
            int r5 = r5.intValue()     // Catch: java.lang.Throwable -> L41
            if (r6 != r5) goto L1b
            int r3 = r3 % 2
            if (r3 != 0) goto L57
            int r8 = java.lang.Math.min(r4, r9)     // Catch: java.lang.Throwable -> L41
            return r8
        L57:
            return r1
        L58:
            com.facebook.internal.instrument.crashshield.a.a(r0, r8)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.C.b(java.util.TreeSet, int, int[]):int");
    }

    public static final Intent d(Context context) {
        ResolveInfo resolveInfoResolveService;
        if (!com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            try {
                Intrinsics.checkNotNullParameter(context, "context");
                Iterator it2 = b.iterator();
                while (it2.hasNext()) {
                    Intent intentAddCategory = new Intent("com.facebook.platform.PLATFORM_SERVICE").setPackage(((B) it2.next()).b()).addCategory("android.intent.category.DEFAULT");
                    if (com.facebook.internal.instrument.crashshield.a.b(C.class)) {
                        intentAddCategory = null;
                    } else {
                        try {
                            Intrinsics.checkNotNullParameter(context, "context");
                            if (intentAddCategory != null && (resolveInfoResolveService = context.getPackageManager().resolveService(intentAddCategory, 0)) != null) {
                                String str = resolveInfoResolveService.serviceInfo.packageName;
                                Intrinsics.checkNotNullExpressionValue(str, "resolveInfo.serviceInfo.packageName");
                                if (!AbstractC1559n.a(context, str)) {
                                }
                            }
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(C.class, th);
                        }
                        intentAddCategory = null;
                    }
                    if (intentAddCategory != null) {
                        return intentAddCategory;
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(C.class, th2);
                return null;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final android.content.Intent e(android.content.Intent r8, android.os.Bundle r9, com.facebook.FacebookException r10) {
        /*
            java.lang.Class<com.facebook.internal.C> r0 = com.facebook.internal.C.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)
            r2 = 0
            if (r1 == 0) goto La
            return r2
        La:
            java.lang.String r1 = "requestIntent"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r1)     // Catch: java.lang.Throwable -> L94
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)     // Catch: java.lang.Throwable -> L94
            java.lang.String r3 = "action_id"
            java.lang.String r4 = "com.facebook.platform.protocol.BRIDGE_ARGS"
            if (r1 == 0) goto L1b
        L19:
            r1 = r2
            goto L48
        L1b:
            if (r8 != 0) goto L1e
            goto L19
        L1e:
            int r1 = i(r8)     // Catch: java.lang.Throwable -> L33
            boolean r1 = j(r1)     // Catch: java.lang.Throwable -> L33
            if (r1 == 0) goto L37
            android.os.Bundle r1 = r8.getBundleExtra(r4)     // Catch: java.lang.Throwable -> L33
            if (r1 == 0) goto L35
            java.lang.String r1 = r1.getString(r3)     // Catch: java.lang.Throwable -> L33
            goto L3d
        L33:
            r1 = move-exception
            goto L44
        L35:
            r1 = r2
            goto L3d
        L37:
            java.lang.String r1 = "com.facebook.platform.protocol.CALL_ID"
            java.lang.String r1 = r8.getStringExtra(r1)     // Catch: java.lang.Throwable -> L33
        L3d:
            if (r1 == 0) goto L19
            java.util.UUID r1 = java.util.UUID.fromString(r1)     // Catch: java.lang.IllegalArgumentException -> L19 java.lang.Throwable -> L33
            goto L48
        L44:
            com.facebook.internal.instrument.crashshield.a.a(r0, r1)     // Catch: java.lang.Throwable -> L94
            goto L19
        L48:
            if (r1 != 0) goto L4b
            return r2
        L4b:
            android.content.Intent r5 = new android.content.Intent     // Catch: java.lang.Throwable -> L94
            r5.<init>()     // Catch: java.lang.Throwable -> L94
            java.lang.String r6 = "com.facebook.platform.protocol.PROTOCOL_VERSION"
            int r8 = i(r8)     // Catch: java.lang.Throwable -> L94
            r5.putExtra(r6, r8)     // Catch: java.lang.Throwable -> L94
            android.os.Bundle r8 = new android.os.Bundle     // Catch: java.lang.Throwable -> L94
            r8.<init>()     // Catch: java.lang.Throwable -> L94
            java.lang.String r1 = r1.toString()     // Catch: java.lang.Throwable -> L94
            r8.putString(r3, r1)     // Catch: java.lang.Throwable -> L94
            if (r10 == 0) goto L96
            java.lang.String r1 = "error"
            boolean r3 = com.facebook.internal.instrument.crashshield.a.b(r0)     // Catch: java.lang.Throwable -> L94
            if (r3 == 0) goto L71
        L6f:
            r3 = r2
            goto L90
        L71:
            android.os.Bundle r3 = new android.os.Bundle     // Catch: java.lang.Throwable -> L8b
            r3.<init>()     // Catch: java.lang.Throwable -> L8b
            java.lang.String r6 = "error_description"
            java.lang.String r7 = r10.toString()     // Catch: java.lang.Throwable -> L8b
            r3.putString(r6, r7)     // Catch: java.lang.Throwable -> L8b
            boolean r10 = r10 instanceof com.facebook.FacebookOperationCanceledException     // Catch: java.lang.Throwable -> L8b
            if (r10 == 0) goto L90
            java.lang.String r10 = "error_type"
            java.lang.String r6 = "UserCanceled"
            r3.putString(r10, r6)     // Catch: java.lang.Throwable -> L8b
            goto L90
        L8b:
            r10 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r0, r10)     // Catch: java.lang.Throwable -> L94
            goto L6f
        L90:
            r8.putBundle(r1, r3)     // Catch: java.lang.Throwable -> L94
            goto L96
        L94:
            r8 = move-exception
            goto La1
        L96:
            r5.putExtra(r4, r8)     // Catch: java.lang.Throwable -> L94
            if (r9 == 0) goto La0
            java.lang.String r8 = "com.facebook.platform.protocol.RESULT_ARGS"
            r5.putExtra(r8, r9)     // Catch: java.lang.Throwable -> L94
        La0:
            return r5
        La1:
            com.facebook.internal.instrument.crashshield.a.a(r0, r8)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.C.e(android.content.Intent, android.os.Bundle, com.facebook.FacebookException):android.content.Intent");
    }

    public static final Bundle h(Intent intent) {
        if (com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(intent, "intent");
            return !j(i(intent)) ? intent.getExtras() : intent.getBundleExtra("com.facebook.platform.protocol.METHOD_ARGS");
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(C.class, th);
            return null;
        }
    }

    public static final int i(Intent intent) {
        if (com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            return 0;
        }
        try {
            Intrinsics.checkNotNullParameter(intent, "intent");
            return intent.getIntExtra("com.facebook.platform.protocol.PROTOCOL_VERSION", 0);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(C.class, th);
            return 0;
        }
    }

    public static final boolean j(int i) {
        if (com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            return false;
        }
        try {
            return C4933y.u(Integer.valueOf(i), d) && i >= 20140701;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(C.class, th);
            return false;
        }
    }

    public static final void k() {
        if (com.facebook.internal.instrument.crashshield.a.b(C.class)) {
            return;
        }
        try {
            if (c.compareAndSet(false, true)) {
                com.facebook.o.c().execute(new RunnableC0131h(17));
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(C.class, th);
        }
    }

    public final ArrayList a() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            return kotlin.collections.B.f(new B(2), new B(4));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final Intent c(B b2, String str, Collection collection, String str2, boolean z, EnumC1567d enumC1567d, String str3, String str4, boolean z2, String str5, boolean z3, com.facebook.login.D d2, boolean z4, boolean z5, String str6) {
        String str7;
        String str8 = "com.facebook.katana.ProxyAuth";
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                switch (b2.b) {
                    case 0:
                    case 3:
                        str8 = null;
                        break;
                    case 1:
                        str8 = "com.instagram.platform.AppAuthorizeActivity";
                        break;
                }
                if (str8 != null) {
                    Intent intentPutExtra = new Intent().setClassName(b2.b(), str8).putExtra("client_id", str);
                    Intrinsics.checkNotNullExpressionValue(intentPutExtra, "Intent()\n            .se…PP_ID_KEY, applicationId)");
                    com.facebook.o oVar = com.facebook.o.a;
                    intentPutExtra.putExtra("facebook_sdk_version", "18.0.3");
                    if (!(collection == null || collection.isEmpty())) {
                        intentPutExtra.putExtra("scope", TextUtils.join(",", collection));
                    }
                    if (!J.D(str2)) {
                        intentPutExtra.putExtra("e2e", str2);
                    }
                    intentPutExtra.putExtra("state", str3);
                    switch (b2.b) {
                        case 1:
                            str7 = "token,signed_request,graph_domain,granted_scopes";
                            break;
                        default:
                            str7 = "id_token,token,signed_request,graph_domain";
                            break;
                    }
                    intentPutExtra.putExtra("response_type", str7);
                    intentPutExtra.putExtra("nonce", str6);
                    intentPutExtra.putExtra("return_scopes", "true");
                    if (z) {
                        intentPutExtra.putExtra("default_audience", enumC1567d.a);
                    }
                    intentPutExtra.putExtra("legacy_override", com.facebook.o.d());
                    intentPutExtra.putExtra("auth_type", str4);
                    if (z2) {
                        intentPutExtra.putExtra("fail_on_logged_out", true);
                    }
                    intentPutExtra.putExtra("messenger_page_id", str5);
                    intentPutExtra.putExtra("reset_messenger_state", z3);
                    if (z4) {
                        intentPutExtra.putExtra("fx_app", d2.a);
                    }
                    if (z5) {
                        intentPutExtra.putExtra("skip_dedupe", true);
                    }
                    return intentPutExtra;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00a7 A[Catch: all -> 0x00ab, TRY_ENTER, TryCatch #4 {all -> 0x00ab, blocks: (B:5:0x0010, B:46:0x00b1, B:47:0x00b4, B:41:0x00a7, B:11:0x004c, B:8:0x002b), top: B:55:0x0010, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0089 A[EXC_TOP_SPLITTER, LOOP:0: B:58:0x0089->B:35:0x008f, LOOP_START, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.TreeSet f(com.facebook.internal.B r15) {
        /*
            r14 = this;
            java.lang.String r1 = ".provider.PlatformProvider"
            java.lang.String r2 = "version"
            java.lang.String r3 = "Failed to query content resolver."
            java.lang.String r4 = "com.facebook.internal.C"
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r14)
            r5 = 0
            if (r0 == 0) goto L10
            return r5
        L10:
            java.util.TreeSet r6 = new java.util.TreeSet     // Catch: java.lang.Throwable -> Lab
            r6.<init>()     // Catch: java.lang.Throwable -> Lab
            android.content.Context r0 = com.facebook.o.a()     // Catch: java.lang.Throwable -> Lab
            android.content.ContentResolver r7 = r0.getContentResolver()     // Catch: java.lang.Throwable -> Lab
            java.lang.String[] r9 = new java.lang.String[]{r2}     // Catch: java.lang.Throwable -> Lab
            java.lang.String r0 = "content://"
            boolean r8 = com.facebook.internal.instrument.crashshield.a.b(r14)     // Catch: java.lang.Throwable -> Lab
            if (r8 == 0) goto L2b
        L29:
            r8 = r5
            goto L50
        L2b:
            java.lang.StringBuilder r8 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L4b
            r8.<init>(r0)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r0 = r15.b()     // Catch: java.lang.Throwable -> L4b
            r8.append(r0)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r0 = ".provider.PlatformProvider/versions"
            r8.append(r0)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r0 = r8.toString()     // Catch: java.lang.Throwable -> L4b
            android.net.Uri r0 = android.net.Uri.parse(r0)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r8 = "parse(CONTENT_SCHEME + a…ATFORM_PROVIDER_VERSIONS)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r8)     // Catch: java.lang.Throwable -> L4b
            r8 = r0
            goto L50
        L4b:
            r0 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r14, r0)     // Catch: java.lang.Throwable -> Lab
            goto L29
        L50:
            android.content.Context r0 = com.facebook.o.a()     // Catch: java.lang.Throwable -> L66
            android.content.pm.PackageManager r0 = r0.getPackageManager()     // Catch: java.lang.Throwable -> L66
            java.lang.String r15 = r15.b()     // Catch: java.lang.Throwable -> L66
            java.lang.String r15 = r15.concat(r1)     // Catch: java.lang.Throwable -> L66
            r1 = 0
            android.content.pm.ProviderInfo r15 = r0.resolveContentProvider(r15, r1)     // Catch: java.lang.Throwable -> L66 java.lang.RuntimeException -> L6a
            goto L70
        L66:
            r0 = move-exception
            r15 = r0
            r0 = r5
            goto Laf
        L6a:
            r0 = move-exception
            r15 = r0
            android.util.Log.e(r4, r3, r15)     // Catch: java.lang.Throwable -> L66
            r15 = r5
        L70:
            if (r15 == 0) goto La4
            r12 = 0
            r10 = 0
            r11 = 0
            android.database.Cursor r15 = r7.query(r8, r9, r10, r11, r12)     // Catch: java.lang.Throwable -> L66 java.lang.IllegalArgumentException -> L7a java.lang.SecurityException -> L7f java.lang.NullPointerException -> L83
            goto L87
        L7a:
            android.util.Log.e(r4, r3)     // Catch: java.lang.Throwable -> L66
        L7d:
            r15 = r5
            goto L87
        L7f:
            android.util.Log.e(r4, r3)     // Catch: java.lang.Throwable -> L66
            goto L7d
        L83:
            android.util.Log.e(r4, r3)     // Catch: java.lang.Throwable -> L66
            goto L7d
        L87:
            if (r15 == 0) goto La5
        L89:
            boolean r0 = r15.moveToNext()     // Catch: java.lang.Throwable -> L9f
            if (r0 == 0) goto La5
            int r0 = r15.getColumnIndex(r2)     // Catch: java.lang.Throwable -> L9f
            int r0 = r15.getInt(r0)     // Catch: java.lang.Throwable -> L9f
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)     // Catch: java.lang.Throwable -> L9f
            r6.add(r0)     // Catch: java.lang.Throwable -> L9f
            goto L89
        L9f:
            r0 = move-exception
            r13 = r0
            r0 = r15
            r15 = r13
            goto Laf
        La4:
            r15 = r5
        La5:
            if (r15 == 0) goto Lae
            r15.close()     // Catch: java.lang.Throwable -> Lab
            goto Lae
        Lab:
            r0 = move-exception
            r15 = r0
            goto Lb5
        Lae:
            return r6
        Laf:
            if (r0 == 0) goto Lb4
            r0.close()     // Catch: java.lang.Throwable -> Lab
        Lb4:
            throw r15     // Catch: java.lang.Throwable -> Lab
        Lb5:
            com.facebook.internal.instrument.crashshield.a.a(r14, r15)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.C.f(com.facebook.internal.B):java.util.TreeSet");
    }

    public final com.airbnb.lottie.parser.l g(ArrayList arrayList, int[] iArr) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            k();
            if (arrayList == null) {
                com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(1);
                lVar.b = -1;
                return lVar;
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                B b2 = (B) it2.next();
                TreeSet treeSet = b2.a;
                int iIntValue = 0;
                if (treeSet == null || treeSet.isEmpty()) {
                    b2.a(false);
                }
                TreeSet treeSet2 = b2.a;
                if (!com.facebook.internal.instrument.crashshield.a.b(C.class)) {
                    try {
                        iIntValue = d[0].intValue();
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(C.class, th);
                    }
                }
                int iB = b(treeSet2, iIntValue, iArr);
                if (iB != -1) {
                    com.airbnb.lottie.parser.l lVar2 = new com.airbnb.lottie.parser.l(1);
                    lVar2.b = iB;
                    return lVar2;
                }
            }
            com.airbnb.lottie.parser.l lVar3 = new com.airbnb.lottie.parser.l(1);
            lVar3.b = -1;
            return lVar3;
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
            return null;
        }
    }
}

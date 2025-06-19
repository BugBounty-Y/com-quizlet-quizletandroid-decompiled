package com.facebook.appevents.iap;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k implements InvocationHandler {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final /* synthetic */ g c;

    public k(m mVar, Object[] objArr) {
        this.c = mVar;
        this.b = objArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0078 A[Catch: all -> 0x002d, Exception -> 0x003f, TryCatch #0 {Exception -> 0x003f, blocks: (B:22:0x0049, B:30:0x005d, B:37:0x006d, B:39:0x0078, B:43:0x007f, B:46:0x008b, B:36:0x0069, B:29:0x0059), top: B:53:0x0049 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0065 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x007f A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:63:0x007e A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(java.lang.Object r6, java.lang.reflect.Method r7, java.lang.Object[] r8) {
        /*
            r5 = this;
            java.lang.String r0 = "productId"
            java.lang.Class<com.facebook.appevents.iap.l> r1 = com.facebook.appevents.iap.l.class
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r5)
            if (r2 == 0) goto Lc
            goto La5
        Lc:
            java.lang.String r2 = "proxy"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r2)     // Catch: java.lang.Throwable -> L2d
            java.lang.String r6 = "m"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r6)     // Catch: java.lang.Throwable -> L2d
            java.lang.String r6 = r7.getName()     // Catch: java.lang.Throwable -> L2d
            java.lang.String r7 = "onSkuDetailsResponse"
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r7)     // Catch: java.lang.Throwable -> L2d
            if (r6 != 0) goto L24
            goto La5
        L24:
            r6 = 0
            if (r8 == 0) goto L30
            r7 = 1
            java.lang.Object r7 = kotlin.collections.C4933y.F(r7, r8)     // Catch: java.lang.Throwable -> L2d
            goto L31
        L2d:
            r6 = move-exception
            goto La6
        L30:
            r7 = r6
        L31:
            if (r7 == 0) goto La5
            boolean r8 = r7 instanceof java.util.List     // Catch: java.lang.Throwable -> L2d
            if (r8 != 0) goto L39
            goto La5
        L39:
            java.util.List r7 = (java.util.List) r7     // Catch: java.lang.Throwable -> L2d
            java.util.Iterator r7 = r7.iterator()     // Catch: java.lang.Throwable -> L2d
        L3f:
            boolean r8 = r7.hasNext()     // Catch: java.lang.Throwable -> L2d
            if (r8 == 0) goto L9e
            java.lang.Object r8 = r7.next()     // Catch: java.lang.Throwable -> L2d
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r1)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            com.facebook.appevents.iap.g r3 = r5.c
            com.facebook.appevents.iap.l r3 = (com.facebook.appevents.iap.l) r3
            if (r2 == 0) goto L55
        L53:
            r2 = r6
            goto L5d
        L55:
            java.lang.Class r2 = r3.c     // Catch: java.lang.Throwable -> L58
            goto L5d
        L58:
            r2 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r2)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            goto L53
        L5d:
            boolean r4 = com.facebook.internal.instrument.crashshield.a.b(r1)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            if (r4 == 0) goto L65
        L63:
            r3 = r6
            goto L6d
        L65:
            java.lang.reflect.Method r3 = r3.g     // Catch: java.lang.Throwable -> L68
            goto L6d
        L68:
            r3 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r3)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            goto L63
        L6d:
            r4 = 0
            java.lang.Object[] r4 = new java.lang.Object[r4]     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            java.lang.Object r8 = com.facebook.appevents.iap.u.h(r2, r8, r3, r4)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            boolean r2 = r8 instanceof java.lang.String     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            if (r2 == 0) goto L7b
            java.lang.String r8 = (java.lang.String) r8     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            goto L7c
        L7b:
            r8 = r6
        L7c:
            if (r8 != 0) goto L7f
            goto L3f
        L7f:
            org.json.JSONObject r2 = new org.json.JSONObject     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            r2.<init>(r8)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            boolean r8 = r2.has(r0)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            if (r8 != 0) goto L8b
            goto L3f
        L8b:
            java.lang.String r8 = r2.getString(r0)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            com.facebook.appevents.iap.p r3 = com.facebook.appevents.iap.l.l     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            java.util.concurrent.ConcurrentHashMap r3 = com.facebook.appevents.iap.p.h()     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            java.lang.String r4 = "skuID"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r4)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            r3.put(r8, r2)     // Catch: java.lang.Throwable -> L2d java.lang.Exception -> L3f
            goto L3f
        L9e:
            java.lang.Object r6 = r5.b     // Catch: java.lang.Throwable -> L2d
            java.lang.Runnable r6 = (java.lang.Runnable) r6     // Catch: java.lang.Throwable -> L2d
            r6.run()     // Catch: java.lang.Throwable -> L2d
        La5:
            return
        La6:
            com.facebook.internal.instrument.crashshield.a.a(r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.k.a(java.lang.Object, java.lang.reflect.Method, java.lang.Object[]):void");
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // java.lang.reflect.InvocationHandler
    public final Object invoke(Object proxy, Method m, Object[] objArr) {
        switch (this.a) {
            case 0:
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        a(proxy, m, objArr);
                        break;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th);
                        return null;
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(proxy, "proxy");
                Intrinsics.checkNotNullParameter(m, "m");
                String name = m.getName();
                if (name != null) {
                    int iHashCode = name.hashCode();
                    Object[] objArr2 = (Object[]) this.b;
                    m mVar = (m) this.c;
                    switch (iHashCode) {
                        case -1642587947:
                            if (name.equals("onPurchaseHistoryResponse") && !com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                                try {
                                    mVar.h(objArr2, objArr);
                                    break;
                                } catch (Throwable th2) {
                                    com.facebook.internal.instrument.crashshield.a.a(m.class, th2);
                                    return null;
                                }
                            }
                            break;
                        case -1599362358:
                            if (name.equals("onQueryPurchasesResponse") && !com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                                try {
                                    mVar.i(objArr2, objArr);
                                    break;
                                } catch (Throwable th3) {
                                    com.facebook.internal.instrument.crashshield.a.a(m.class, th3);
                                    return null;
                                }
                            }
                            break;
                        case -79406125:
                            if (name.equals("onBillingSetupFinished") && !com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                                try {
                                    mVar.f(objArr2, objArr);
                                    break;
                                } catch (Throwable th4) {
                                    com.facebook.internal.instrument.crashshield.a.a(m.class, th4);
                                    return null;
                                }
                            }
                            break;
                        case 1227540564:
                            if (name.equals("onBillingServiceDisconnected") && !com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                                try {
                                    mVar.getClass();
                                    if (!com.facebook.internal.instrument.crashshield.a.b(mVar)) {
                                        try {
                                            m.H.set(false);
                                            break;
                                        } catch (Throwable th5) {
                                            com.facebook.internal.instrument.crashshield.a.a(mVar, th5);
                                            return null;
                                        }
                                    }
                                } catch (Throwable th6) {
                                    com.facebook.internal.instrument.crashshield.a.a(m.class, th6);
                                    return null;
                                }
                            }
                            break;
                        case 1940131955:
                            if (name.equals("onProductDetailsResponse") && !com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                                try {
                                    mVar.g(objArr2, objArr);
                                    break;
                                } catch (Throwable th7) {
                                    com.facebook.internal.instrument.crashshield.a.a(m.class, th7);
                                    return null;
                                }
                            }
                            break;
                    }
                }
                break;
        }
        return null;
    }

    public k(l lVar, Runnable completionHandler) {
        Intrinsics.checkNotNullParameter(completionHandler, "completionHandler");
        this.c = lVar;
        this.b = completionHandler;
    }
}

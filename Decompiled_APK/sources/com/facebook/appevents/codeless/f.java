package com.facebook.appevents.codeless;

import android.os.Handler;
import android.view.View;
import android.view.ViewTreeObserver;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import com.google.android.gms.internal.mlkit_vision_common.B2;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashSet;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener, Runnable {
    public final WeakReference a;
    public ArrayList b;
    public final HashSet c;
    public final String d;

    public f(View view, Handler handler, HashSet listenerSet, String activityName) {
        Intrinsics.checkNotNullParameter(handler, "handler");
        Intrinsics.checkNotNullParameter(listenerSet, "listenerSet");
        Intrinsics.checkNotNullParameter(activityName, "activityName");
        this.a = new WeakReference(view);
        this.c = listenerSet;
        this.d = activityName;
        handler.postDelayed(this, 200L);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(com.facebook.appevents.codeless.e r6, android.view.View r7, com.facebook.appevents.codeless.internal.c r8) {
        /*
            r5 = this;
            android.view.View r0 = r6.a()
            if (r0 != 0) goto L7
            goto L53
        L7:
            android.view.View$OnClickListener r1 = com.facebook.appevents.codeless.internal.g.e(r0)
            boolean r2 = r1 instanceof com.facebook.appevents.codeless.a
            if (r2 == 0) goto L1c
            java.lang.String r2 = "null cannot be cast to non-null type com.facebook.appevents.codeless.CodelessLoggingEventListener.AutoLoggingOnClickListener"
            kotlin.jvm.internal.Intrinsics.e(r1, r2)
            com.facebook.appevents.codeless.a r1 = (com.facebook.appevents.codeless.a) r1
            boolean r1 = r1.e
            if (r1 == 0) goto L1c
            r1 = 1
            goto L1d
        L1c:
            r1 = 0
        L1d:
            java.util.HashSet r2 = r5.c
            java.lang.String r6 = r6.b
            boolean r3 = r2.contains(r6)
            if (r3 != 0) goto L53
            if (r1 != 0) goto L53
            java.lang.Class<com.facebook.appevents.codeless.c> r1 = com.facebook.appevents.codeless.c.class
            boolean r3 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r4 = 0
            if (r3 == 0) goto L33
            goto L4d
        L33:
            java.lang.String r3 = "mapping"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r3)     // Catch: java.lang.Throwable -> L49
            java.lang.String r3 = "rootView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r3)     // Catch: java.lang.Throwable -> L49
            java.lang.String r3 = "hostView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)     // Catch: java.lang.Throwable -> L49
            com.facebook.appevents.codeless.a r3 = new com.facebook.appevents.codeless.a     // Catch: java.lang.Throwable -> L49
            r3.<init>(r8, r7, r0)     // Catch: java.lang.Throwable -> L49
            r4 = r3
            goto L4d
        L49:
            r7 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r7)
        L4d:
            r0.setOnClickListener(r4)
            r2.add(r6)
        L53:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.f.a(com.facebook.appevents.codeless.e, android.view.View, com.facebook.appevents.codeless.internal.c):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(com.facebook.appevents.codeless.e r6, android.view.View r7, com.facebook.appevents.codeless.internal.c r8) {
        /*
            r5 = this;
            android.view.View r0 = r6.a()
            android.widget.AdapterView r0 = (android.widget.AdapterView) r0
            if (r0 != 0) goto L9
            goto L55
        L9:
            android.widget.AdapterView$OnItemClickListener r1 = r0.getOnItemClickListener()
            boolean r2 = r1 instanceof com.facebook.appevents.codeless.b
            if (r2 == 0) goto L1e
            java.lang.String r2 = "null cannot be cast to non-null type com.facebook.appevents.codeless.CodelessLoggingEventListener.AutoLoggingOnItemClickListener"
            kotlin.jvm.internal.Intrinsics.e(r1, r2)
            com.facebook.appevents.codeless.b r1 = (com.facebook.appevents.codeless.b) r1
            boolean r1 = r1.e
            if (r1 == 0) goto L1e
            r1 = 1
            goto L1f
        L1e:
            r1 = 0
        L1f:
            java.util.HashSet r2 = r5.c
            java.lang.String r6 = r6.b
            boolean r3 = r2.contains(r6)
            if (r3 != 0) goto L55
            if (r1 != 0) goto L55
            java.lang.Class<com.facebook.appevents.codeless.c> r1 = com.facebook.appevents.codeless.c.class
            boolean r3 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r4 = 0
            if (r3 == 0) goto L35
            goto L4f
        L35:
            java.lang.String r3 = "mapping"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r3)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r3 = "rootView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r3)     // Catch: java.lang.Throwable -> L4b
            java.lang.String r3 = "hostView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)     // Catch: java.lang.Throwable -> L4b
            com.facebook.appevents.codeless.b r3 = new com.facebook.appevents.codeless.b     // Catch: java.lang.Throwable -> L4b
            r3.<init>(r8, r7, r0)     // Catch: java.lang.Throwable -> L4b
            r4 = r3
            goto L4f
        L4b:
            r7 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r7)
        L4f:
            r0.setOnItemClickListener(r4)
            r2.add(r6)
        L55:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.f.b(com.facebook.appevents.codeless.e, android.view.View, com.facebook.appevents.codeless.internal.c):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(com.facebook.appevents.codeless.e r6, android.view.View r7, com.facebook.appevents.codeless.internal.c r8) {
        /*
            r5 = this;
            android.view.View r0 = r6.a()
            if (r0 != 0) goto L7
            goto L53
        L7:
            android.view.View$OnTouchListener r1 = com.facebook.appevents.codeless.internal.g.f(r0)
            boolean r2 = r1 instanceof com.facebook.appevents.codeless.h
            if (r2 == 0) goto L1c
            java.lang.String r2 = "null cannot be cast to non-null type com.facebook.appevents.codeless.RCTCodelessLoggingEventListener.AutoLoggingOnTouchListener"
            kotlin.jvm.internal.Intrinsics.e(r1, r2)
            com.facebook.appevents.codeless.h r1 = (com.facebook.appevents.codeless.h) r1
            boolean r1 = r1.e
            if (r1 == 0) goto L1c
            r1 = 1
            goto L1d
        L1c:
            r1 = 0
        L1d:
            java.util.HashSet r2 = r5.c
            java.lang.String r6 = r6.b
            boolean r3 = r2.contains(r6)
            if (r3 != 0) goto L53
            if (r1 != 0) goto L53
            java.lang.Class<com.facebook.appevents.codeless.i> r1 = com.facebook.appevents.codeless.i.class
            boolean r3 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r4 = 0
            if (r3 == 0) goto L33
            goto L4d
        L33:
            java.lang.String r3 = "mapping"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r3)     // Catch: java.lang.Throwable -> L49
            java.lang.String r3 = "rootView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r3)     // Catch: java.lang.Throwable -> L49
            java.lang.String r3 = "hostView"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)     // Catch: java.lang.Throwable -> L49
            com.facebook.appevents.codeless.h r3 = new com.facebook.appevents.codeless.h     // Catch: java.lang.Throwable -> L49
            r3.<init>(r8, r7, r0)     // Catch: java.lang.Throwable -> L49
            r4 = r3
            goto L4d
        L49:
            r7 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r7)
        L4d:
            r0.setOnTouchListener(r4)
            r2.add(r6)
        L53:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.f.c(com.facebook.appevents.codeless.e, android.view.View, com.facebook.appevents.codeless.internal.c):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00a2 A[Catch: all -> 0x00ae, TryCatch #2 {all -> 0x00ae, blocks: (B:35:0x0080, B:44:0x00a2, B:46:0x00aa, B:41:0x009a, B:38:0x008a), top: B:71:0x0080, outer: #0, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:91:0x00a0 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d() {
        /*
            Method dump skipped, instructions count: 247
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.codeless.f.d():void");
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        d();
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final void onScrollChanged() {
        d();
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            v vVarB = y.b(o.b());
            if (vVarB != null && vVarB.g) {
                JSONArray jSONArray = vVarB.h;
                ArrayList arrayList = new ArrayList();
                if (jSONArray != null) {
                    try {
                        int length = jSONArray.length();
                        for (int i = 0; i < length; i++) {
                            JSONObject jSONObject = jSONArray.getJSONObject(i);
                            Intrinsics.checkNotNullExpressionValue(jSONObject, "array.getJSONObject(i)");
                            arrayList.add(B2.a(jSONObject));
                        }
                    } catch (IllegalArgumentException | JSONException unused) {
                    }
                }
                this.b = arrayList;
                View view = (View) this.a.get();
                if (view == null) {
                    return;
                }
                ViewTreeObserver viewTreeObserver = view.getViewTreeObserver();
                if (viewTreeObserver.isAlive()) {
                    viewTreeObserver.addOnGlobalLayoutListener(this);
                    viewTreeObserver.addOnScrollChangedListener(this);
                }
                d();
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}

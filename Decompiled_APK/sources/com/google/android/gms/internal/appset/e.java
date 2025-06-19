package com.google.android.gms.internal.appset;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.location.LocationManager;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import androidx.appcompat.app.O;
import androidx.camera.camera2.internal.p0;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.compose.foundation.lazy.grid.m;
import androidx.compose.foundation.lazy.layout.C0429a;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.data.i;
import com.bumptech.glide.load.resource.bitmap.v;
import com.bumptech.glide.load.resource.bitmap.w;
import com.bumptech.glide.util.j;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.C3319a2;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import com.google.android.gms.measurement.internal.F0;
import com.google.android.gms.tasks.Task;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.google.firebase.encoders.EncodingException;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.data.interactor.folderstudymaterial.o;
import com.quizlet.data.model.m2;
import com.quizlet.data.model.q2;
import com.quizlet.data.model.r2;
import com.quizlet.data.model.s2;
import com.quizlet.data.model.t2;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.remote.service.InterfaceC4774a;
import com.quizlet.remote.service.y;
import io.reactivex.rxjava3.functions.h;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.n;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5155c;
import org.wordpress.aztec.spans.K;
import org.wordpress.aztec.spans.N;

/* loaded from: classes2.dex */
public final class e implements com.google.android.gms.appset.a, androidx.camera.core.impl.utils.futures.c, v, com.google.firebase.encoders.config.a, F0, h {
    public static e e;
    public static e f;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ e(int i, boolean z) {
        this.a = i;
    }

    public static String j(DBUser dBUser) {
        int birthYear = dBUser.getBirthYear();
        int birthMonth = dBUser.getBirthMonth();
        int birthDay = dBUser.getBirthDay();
        GregorianCalendar dateFrom = new GregorianCalendar();
        Intrinsics.checkNotNullParameter(dateFrom, "dateFrom");
        long days = TimeUnit.MILLISECONDS.toDays(dateFrom.getTimeInMillis() - new GregorianCalendar(birthYear, birthMonth, birthDay).getTimeInMillis());
        return days >= 12410 ? "34+" : days >= 9125 ? "25-34" : days >= 6570 ? "18-24" : days >= 4745 ? "13-17" : "u13";
    }

    public static void k(StringBuilder sb, Spanned spanned, int i) {
        if (spanned instanceof SpannableStringBuilder) {
            SpannableStringBuilder spannableStringBuilder = (SpannableStringBuilder) spanned;
            Object[] spans = spannableStringBuilder.getSpans(i, i, C5155c.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            C5155c c5155c = (C5155c) C4933y.B(spans);
            if (c5155c != null) {
                sb.append("aztec_cursor");
                spannableStringBuilder.removeSpan(c5155c);
            }
        }
    }

    public static void m(SpannableStringBuilder spannable, N n, int i) {
        Object[] spanObjects = spannable.getSpans(spannable.getSpanStart(n), i, K.class);
        Intrinsics.checkNotNullExpressionValue(spanObjects, "getSpans(...)");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(spanObjects, "spanObjects");
        ArrayList arrayList = new ArrayList(spanObjects.length);
        for (Object obj : spanObjects) {
            arrayList.add(new org.wordpress.aztec.util.d(spannable, obj));
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            org.wordpress.aztec.util.d dVar = (org.wordpress.aztec.util.d) next;
            if (dVar.a() == i && ((K) dVar.b).a() < n.a()) {
                arrayList2.add(next);
            }
        }
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            org.wordpress.aztec.util.d dVar2 = (org.wordpress.aztec.util.d) it3.next();
            dVar2.d(dVar2.a() + 1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0094  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void u(android.text.SpannableStringBuilder r17) {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.u(android.text.SpannableStringBuilder):void");
    }

    public static String v(String str) {
        return new Regex("(</? ?br>)*((aztec_cursor)?)</pre>").replace(new Regex("(</? ?br>)*((aztec_cursor)?)</p>").replace(new Regex("(</? ?br>)*((aztec_cursor)?)</li>").replace(new Regex("(</? ?br>)*((aztec_cursor)?)</blockquote>").replace(D.o(D.o(str, C2.d, "", false), C2.a, "", false), "$2</blockquote>"), "$2</li>"), "$2</p>"), "$2</pre>");
    }

    public static final SharedPreferences y(Context context) {
        return context.getSharedPreferences("app_set_id_storage", 0);
    }

    public static final void z(Context context) throws d {
        if (y(context).edit().putLong("app_set_id_last_used_time", System.currentTimeMillis()).commit()) {
            return;
        }
        String strValueOf = String.valueOf(context.getPackageName());
        Log.e("AppSet", strValueOf.length() != 0 ? "Failed to store app set ID last used time for App ".concat(strValueOf) : new String("Failed to store app set ID last used time for App "));
        throw new d("Failed to store the app set ID last used time.");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001a  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x006d  */
    @Override // com.google.android.gms.measurement.internal.F0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(int r9, java.io.IOException r10, byte[] r11) {
        /*
            r8 = this;
            java.lang.Object r11 = r8.b
            com.google.android.gms.measurement.internal.D0 r11 = (com.google.android.gms.measurement.internal.D0) r11
            r11.S()
            java.lang.Object r0 = r8.d
            com.google.android.gms.measurement.internal.zzpa r0 = (com.google.android.gms.measurement.internal.zzpa) r0
            r1 = 200(0xc8, float:2.8E-43)
            if (r9 == r1) goto L18
            r1 = 204(0xcc, float:2.86E-43)
            if (r9 == r1) goto L18
            r1 = 304(0x130, float:4.26E-43)
            if (r9 != r1) goto L33
            r9 = r1
        L18:
            if (r10 != 0) goto L33
            java.lang.Object r9 = r11.b
            com.google.android.gms.measurement.internal.Y r9 = (com.google.android.gms.measurement.internal.Y) r9
            com.google.android.gms.measurement.internal.I r9 = r9.i
            com.google.android.gms.measurement.internal.Y.k(r9)
            com.google.android.gms.internal.ads.Ka r9 = r9.o
            long r1 = r0.a
            java.lang.Long r10 = java.lang.Long.valueOf(r1)
            java.lang.String r1 = "[sgtm] Upload succeeded for row_id"
            r9.g(r1, r10)
            com.google.android.gms.measurement.internal.J0 r9 = com.google.android.gms.measurement.internal.J0.SUCCESS
            goto L6f
        L33:
            java.lang.Object r1 = r11.b
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.measurement.internal.I r1 = r1.i
            com.google.android.gms.measurement.internal.Y.k(r1)
            com.google.android.gms.internal.ads.Ka r1 = r1.j
            long r2 = r0.a
            java.lang.Long r2 = java.lang.Long.valueOf(r2)
            java.lang.Integer r3 = java.lang.Integer.valueOf(r9)
            java.lang.String r4 = "[sgtm] Upload failed for row_id. response, exception"
            r1.i(r4, r2, r3, r10)
            com.google.android.gms.measurement.internal.s r10 = com.google.android.gms.measurement.internal.AbstractC3893t.u
            r1 = 0
            java.lang.Object r10 = r10.a(r1)
            java.lang.String r10 = (java.lang.String) r10
            java.lang.String r1 = ","
            java.lang.String[] r10 = r10.split(r1)
            java.util.List r10 = java.util.Arrays.asList(r10)
            java.lang.String r9 = java.lang.String.valueOf(r9)
            boolean r9 = r10.contains(r9)
            if (r9 == 0) goto L6d
            com.google.android.gms.measurement.internal.J0 r9 = com.google.android.gms.measurement.internal.J0.BACKOFF
            goto L6f
        L6d:
            com.google.android.gms.measurement.internal.J0 r9 = com.google.android.gms.measurement.internal.J0.FAILURE
        L6f:
            java.lang.Object r10 = r8.c
            java.util.concurrent.atomic.AtomicReference r10 = (java.util.concurrent.atomic.AtomicReference) r10
            java.lang.Object r1 = r11.b
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            com.google.android.gms.measurement.internal.Y0 r1 = r1.r()
            com.google.android.gms.measurement.internal.zzag r2 = new com.google.android.gms.measurement.internal.zzag
            long r3 = r0.a
            int r7 = r9.a
            long r5 = r0.f
            r2.<init>(r3, r5, r7)
            r1.S()
            r1.Q()
            r0 = 1
            com.google.android.gms.measurement.internal.zzr r0 = r1.f0(r0)
            androidx.core.provider.k r5 = new androidx.core.provider.k
            r6 = 18
            r5.<init>(r1, r0, r2, r6)
            r1.i0(r5)
            java.lang.Object r11 = r11.b
            com.google.android.gms.measurement.internal.Y r11 = (com.google.android.gms.measurement.internal.Y) r11
            com.google.android.gms.measurement.internal.I r11 = r11.i
            com.google.android.gms.measurement.internal.Y.k(r11)
            com.google.android.gms.internal.ads.Ka r11 = r11.o
            java.lang.Long r0 = java.lang.Long.valueOf(r3)
            java.lang.String r1 = "[sgtm] Updated status for row_id"
            r11.h(r1, r0, r9)
            monitor-enter(r10)
            r10.set(r9)     // Catch: java.lang.Throwable -> Lb8
            r10.notifyAll()     // Catch: java.lang.Throwable -> Lb8
            monitor-exit(r10)     // Catch: java.lang.Throwable -> Lb8
            return
        Lb8:
            r0 = move-exception
            r9 = r0
            monitor-exit(r10)     // Catch: java.lang.Throwable -> Lb8
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.a(int, java.io.IOException, byte[]):void");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        File it2 = (File) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return com.quizlet.quizletandroid.managers.audio.g.c((com.quizlet.quizletandroid.managers.audio.g) this.b, (String) this.c, it2, (com.quizlet.quizletandroid.data.cache.a) this.d);
    }

    @Override // com.google.android.gms.appset.a
    public Task b() {
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        ((ExecutorService) this.d).execute(new com.google.common.util.concurrent.d(23, this, fVar));
        return fVar.a;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public int c() {
        w wVar = (w) ((i) this.b).b;
        wVar.reset();
        return AbstractC3567z.a((ArrayList) this.d, wVar, (m) this.c);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public Bitmap d(BitmapFactory.Options options) {
        w wVar = (w) ((i) this.b).b;
        wVar.reset();
        return BitmapFactory.decodeStream(wVar, null, options);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public void e() {
        w wVar = (w) ((i) this.b).b;
        synchronized (wVar) {
            wVar.c = wVar.a.length;
        }
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public ImageHeaderParser$ImageType f() {
        w wVar = (w) ((i) this.b).b;
        wVar.reset();
        return AbstractC3567z.b((ArrayList) this.d, wVar, (m) this.c);
    }

    @Override // com.google.firebase.encoders.config.a
    public /* bridge */ /* synthetic */ com.google.firebase.encoders.config.a g(Class cls, com.google.firebase.encoders.c cVar) {
        ((HashMap) this.b).put(cls, cVar);
        ((HashMap) this.c).remove(cls);
        return this;
    }

    public String h() {
        String str = (String) this.c;
        if (str == null) {
            return str;
        }
        if ("".equalsIgnoreCase(str.trim())) {
            return null;
        }
        return (String) this.c;
    }

    public boolean i() {
        return !String.valueOf(false).equalsIgnoreCase((String) this.b);
    }

    public void l(Object obj, ByteArrayOutputStream byteArrayOutputStream) {
        HashMap map = (HashMap) this.c;
        HashMap map2 = (HashMap) this.b;
        com.google.firebase.encoders.proto.e eVar = new com.google.firebase.encoders.proto.e(byteArrayOutputStream, map2, map, (com.google.firebase.encoders.json.a) this.d);
        if (obj == null) {
            return;
        }
        com.google.firebase.encoders.c cVar = (com.google.firebase.encoders.c) map2.get(obj.getClass());
        if (cVar != null) {
            cVar.a(obj, eVar);
        } else {
            throw new EncodingException("No encoder for " + obj.getClass());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:74:0x0280  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.text.SpannableStringBuilder n(android.content.Context r22, java.lang.String r23) {
        /*
            Method dump skipped, instructions count: 1169
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.n(android.content.Context, java.lang.String):android.text.SpannableStringBuilder");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(long r6, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            r0 = 3
            boolean r1 = r8 instanceof com.quizlet.features.folders.viewmodel.usecases.m
            if (r1 == 0) goto L14
            r1 = r8
            com.quizlet.features.folders.viewmodel.usecases.m r1 = (com.quizlet.features.folders.viewmodel.usecases.m) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L14
            int r2 = r2 - r3
            r1.n = r2
            goto L19
        L14:
            com.quizlet.features.folders.viewmodel.usecases.m r1 = new com.quizlet.features.folders.viewmodel.usecases.m
            r1.<init>(r5, r8)
        L19:
            java.lang.Object r8 = r1.l
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.n
            r4 = 1
            if (r3 == 0) goto L34
            if (r3 != r4) goto L2c
            long r6 = r1.k
            com.google.android.gms.internal.appset.e r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L49
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r1.j = r5
            r1.k = r6
            r1.n = r4
            java.lang.Object r8 = r5.b
            com.quizlet.data.repository.user.a r8 = (com.quizlet.data.repository.user.a) r8
            java.lang.Object r8 = r8.j(r1)
            if (r8 != r2) goto L48
            return r2
        L48:
            r1 = r5
        L49:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto L6b
            kotlin.p r6 = kotlin.r.b
            java.lang.Exception r6 = new java.lang.Exception
            java.lang.String r7 = "Not in Subfolder Feature"
            r6.<init>(r7)
            kotlin.q r6 = androidx.glance.appwidget.protobuf.Z.b(r6)
            kotlin.r r7 = new kotlin.r
            r7.<init>(r6)
            androidx.datastore.core.t r6 = new androidx.datastore.core.t
            r8 = 10
            r6.<init>(r7, r8)
            return r6
        L6b:
            java.lang.Object r8 = r1.c
            com.quizlet.data.interactor.folderstudymaterial.o r8 = (com.quizlet.data.interactor.folderstudymaterial.o) r8
            com.quizlet.generated.enums.y1 r2 = com.quizlet.generated.enums.y1.FOLDER
            java.util.List r2 = kotlin.collections.A.b(r2)
            androidx.paging.J0 r6 = r8.c(r6, r2)
            androidx.compose.material3.internal.H r7 = new androidx.compose.material3.internal.H
            r7.<init>(r0, r6, r1)
            kotlinx.coroutines.flow.i r6 = kotlinx.coroutines.flow.e0.m(r7)
            com.google.firebase.sessions.H r7 = new com.google.firebase.sessions.H
            r8 = 0
            r1 = 4
            r7.<init>(r0, r1, r8)
            androidx.paging.J0 r8 = new androidx.paging.J0
            r8.<init>(r6, r7)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.o(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        ((p0) this.d).f = null;
        ArrayList arrayList = (ArrayList) this.b;
        if (arrayList.isEmpty()) {
            return;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((InterfaceC0183w) this.c).j((AbstractC0171j) it2.next());
        }
        arrayList.clear();
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((p0) this.d).f = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(io.reactivex.rxjava3.core.p r6, kotlin.jvm.functions.Function0 r7, kotlin.jvm.functions.Function1 r8, kotlin.jvm.functions.Function1 r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r10 instanceof com.quizlet.remote.model.achievements.b
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.remote.model.achievements.b r0 = (com.quizlet.remote.model.achievements.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.remote.model.achievements.b r0 = new com.quizlet.remote.model.achievements.b
            r0.<init>(r5, r10)
        L18:
            java.lang.Object r10 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlin.jvm.functions.Function1 r8 = r0.k
            kotlin.jvm.functions.Function0 r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L2b
            return r10
        L2b:
            r6 = move-exception
            goto L50
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r5.d     // Catch: java.lang.Exception -> L2b
            kotlinx.coroutines.y r10 = (kotlinx.coroutines.AbstractC5040y) r10     // Catch: java.lang.Exception -> L2b
            com.quizlet.remote.model.achievements.c r2 = new com.quizlet.remote.model.achievements.c     // Catch: java.lang.Exception -> L2b
            r4 = 0
            r2.<init>(r6, r9, r4)     // Catch: java.lang.Exception -> L2b
            r0.j = r7     // Catch: java.lang.Exception -> L2b
            r0.k = r8     // Catch: java.lang.Exception -> L2b
            r0.n = r3     // Catch: java.lang.Exception -> L2b
            java.lang.Object r6 = kotlinx.coroutines.E.J(r10, r2, r0)     // Catch: java.lang.Exception -> L2b
            if (r6 != r1) goto L4f
            return r1
        L4f:
            return r6
        L50:
            boolean r9 = r6 instanceof com.quizlet.remote.service.NetworkException
            if (r9 == 0) goto L6d
            r9 = r6
            com.quizlet.remote.service.NetworkException r9 = (com.quizlet.remote.service.NetworkException) r9
            com.quizlet.remote.model.base.ApiError r9 = r9.a
            if (r9 == 0) goto L6d
            java.lang.Integer r9 = r9.c
            if (r9 != 0) goto L60
            goto L6d
        L60:
            int r9 = r9.intValue()
            r10 = 412(0x19c, float:5.77E-43)
            if (r9 != r10) goto L6d
            java.lang.Object r6 = r7.invoke()
            goto L71
        L6d:
            java.lang.Object r6 = r8.invoke(r6)
        L71:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.p(io.reactivex.rxjava3.core.p, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    public Object q(m2 m2Var, t2 t2Var, kotlin.coroutines.jvm.internal.i iVar) {
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0) {
            throw new n(null, 1, null);
        }
        if (iOrdinal == 1) {
            throw new n(null, 1, null);
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (t2Var instanceof s2) {
            s2 s2Var = (s2) t2Var;
            com.quizlet.remote.model.notes.e eVar = ((com.quizlet.data.interactor.universaluploadflow.d) ((dagger.internal.a) this.b).get()).a;
            return E.J((AbstractC5040y) eVar.c, new com.quizlet.remote.model.universaluploadflow.a(eVar, s2Var.a, null, s2Var.b), iVar);
        }
        if (t2Var instanceof q2) {
            q2 q2Var = (q2) t2Var;
            return ((com.quizlet.data.interactor.universaluploadflow.b) ((dagger.internal.a) this.c).get()).a(q2Var.a, q2Var.b, iVar);
        }
        if (!(t2Var instanceof r2)) {
            throw new NoWhenBranchMatchedException();
        }
        com.quizlet.data.interactor.universaluploadflow.c cVar = (com.quizlet.data.interactor.universaluploadflow.c) ((dagger.internal.a) this.d).get();
        r2 r2Var = (r2) t2Var;
        ?? r0 = r2Var.a;
        com.quizlet.remote.model.notes.e eVar2 = cVar.a;
        return E.J((AbstractC5040y) eVar2.c, new com.quizlet.remote.model.universaluploadflow.c(eVar2, r0, null, r2Var.b), iVar);
    }

    public void r(String authProvider, boolean z) {
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        ((EventLogger) this.b).d(authProvider, z);
    }

    public void s(String signupOrigin, DBUser user) {
        Intrinsics.checkNotNullParameter(signupOrigin, "authProvider");
        Intrinsics.checkNotNullParameter(user, "user");
        ((EventLogger) this.b).f(signupOrigin, false);
        long id = user.getId();
        int selfIdentifiedUserType = user.getSelfIdentifiedUserType();
        String ageBucket = j(user);
        com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) this.c;
        Intrinsics.checkNotNullParameter(signupOrigin, "signupOrigin");
        Intrinsics.checkNotNullParameter(ageBucket, "ageBucket");
        Bundle bundleV = aVar.v(selfIdentifiedUserType, id, ageBucket);
        bundleV.putString("screenName", "login");
        String str = "facebook";
        if (!Intrinsics.b(signupOrigin, "facebook")) {
            str = OTVendorListMode.GOOGLE;
            if (!Intrinsics.b(signupOrigin, OTVendorListMode.GOOGLE)) {
                str = "username_and_password";
            }
        }
        bundleV.putString("loginOrigin", str);
        timber.log.c.a.g("Logging login event w/ bundle %s", bundleV);
        ((FirebaseAnalytics) aVar.d).a(bundleV, "login");
        com.quizlet.infra.contracts.marketing.a event = com.quizlet.infra.contracts.marketing.a.b;
        com.quizlet.data.repository.classfolder.e eVar = (com.quizlet.data.repository.classfolder.e) this.d;
        Intrinsics.checkNotNullParameter(event, "event");
        eVar.p(new com.braze.triggers.managers.h(12, eVar, event));
    }

    public void t(String signupOrigin, DBUser user) {
        Intrinsics.checkNotNullParameter(signupOrigin, "authProvider");
        Intrinsics.checkNotNullParameter(user, "user");
        ((EventLogger) this.b).f(signupOrigin, true);
        long id = user.getId();
        int selfIdentifiedUserType = user.getSelfIdentifiedUserType();
        String ageBucket = j(user);
        com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) this.c;
        Intrinsics.checkNotNullParameter(signupOrigin, "signupOrigin");
        Intrinsics.checkNotNullParameter(ageBucket, "ageBucket");
        Bundle bundleV = aVar.v(selfIdentifiedUserType, id, ageBucket);
        bundleV.putString("screenName", "signup");
        String str = "facebook";
        if (!Intrinsics.b(signupOrigin, "facebook")) {
            str = OTVendorListMode.GOOGLE;
            if (!Intrinsics.b(signupOrigin, OTVendorListMode.GOOGLE)) {
                str = "username_and_password";
            }
        }
        bundleV.putString("signupOrigin", str);
        timber.log.c.a.g("Logging signup event w/ bundle %s", bundleV);
        ((FirebaseAnalytics) aVar.d).a(bundleV, "signup");
        com.quizlet.infra.contracts.marketing.a event = com.quizlet.infra.contracts.marketing.a.a;
        com.quizlet.data.repository.classfolder.e eVar = (com.quizlet.data.repository.classfolder.e) this.d;
        Intrinsics.checkNotNullParameter(event, "event");
        eVar.p(new com.braze.triggers.managers.h(12, eVar, event));
    }

    public String toString() {
        switch (this.a) {
            case 10:
                StringBuilder sb = new StringBuilder("LogoProperty{show='");
                sb.append((String) this.b);
                sb.append("', url='");
                sb.append((String) this.c);
                sb.append("', height='null', width='null', contentDescription='");
                return android.support.v4.media.session.a.t(sb, (String) this.d, "'}");
            default:
                return super.toString();
        }
    }

    public String w(Spanned text) {
        Intrinsics.checkNotNullParameter(text, "text");
        StringBuilder sb = new StringBuilder();
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(text);
        ArrayList arrayList = new ArrayList();
        List list = (List) this.c;
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (it2.next() != null) {
                throw new ClassCastException();
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            if (it3.next() != null) {
                throw new ClassCastException();
            }
            Intrinsics.e(null, "null cannot be cast to non-null type org.wordpress.aztec.plugins.visual2html.ISpanPreprocessor");
            arrayList2.add(null);
        }
        Iterator it4 = arrayList2.iterator();
        if (it4.hasNext()) {
            throw android.support.v4.media.session.a.d(it4);
        }
        Object[] spans = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), ForegroundColorSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        for (Object obj : spans) {
            spannableStringBuilder.removeSpan((ForegroundColorSpan) obj);
        }
        Object[] spans2 = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), C5155c.class);
        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
        C5155c c5155c = (C5155c) C4933y.B(spans2);
        if (c5155c != null) {
            spannableStringBuilder.removeSpan(c5155c);
        }
        x(sb, spannableStringBuilder, 0, spannableStringBuilder.length(), null, -1);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        String strV = v(string);
        Intrinsics.d(strV);
        ArrayList arrayList3 = new ArrayList();
        Iterator it5 = list.iterator();
        while (it5.hasNext()) {
            if (it5.next() != null) {
                throw new ClassCastException();
            }
        }
        ArrayList arrayList4 = new ArrayList(C.q(arrayList3, 10));
        Iterator it6 = arrayList3.iterator();
        while (it6.hasNext()) {
            if (it6.next() != null) {
                throw new ClassCastException();
            }
            Intrinsics.e(null, "null cannot be cast to non-null type org.wordpress.aztec.plugins.visual2html.IHtmlPostprocessor");
            arrayList4.add(null);
        }
        Iterator it7 = arrayList4.iterator();
        if (it7.hasNext()) {
            throw android.support.v4.media.session.a.d(it7);
        }
        return strV;
    }

    /* JADX WARN: Code restructure failed: missing block: B:144:0x0337, code lost:
    
        r26 = r3;
        r24 = r4;
        r22 = r5;
        r20 = r8;
        r23 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:298:0x0620, code lost:
    
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:299:0x0621, code lost:
    
        if (r2 >= r10) goto L351;
     */
    /* JADX WARN: Code restructure failed: missing block: B:300:0x0623, code lost:
    
        if (r22 == null) goto L310;
     */
    /* JADX WARN: Code restructure failed: missing block: B:302:0x0629, code lost:
    
        if (r22.isEmpty() == false) goto L304;
     */
    /* JADX WARN: Code restructure failed: missing block: B:304:0x062c, code lost:
    
        r3 = r22.iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:306:0x0634, code lost:
    
        if (r3.hasNext() == false) goto L354;
     */
    /* JADX WARN: Code restructure failed: missing block: B:308:0x0642, code lost:
    
        if (r0.getSpanEnd((org.wordpress.aztec.spans.K) r3.next()) != (r12 + r2)) goto L355;
     */
    /* JADX WARN: Code restructure failed: missing block: B:310:0x0645, code lost:
    
        r30.append("<br>");
        k(r30, r0, r12 + r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:311:0x064d, code lost:
    
        r2 = r2 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:312:0x0650, code lost:
    
        r7 = r20;
        r5 = r22;
        r14 = r23;
        r4 = r24;
        r3 = r26;
        r2 = 0;
     */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0159  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0174  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void x(java.lang.StringBuilder r30, android.text.SpannableStringBuilder r31, int r32, int r33, java.util.ArrayList r34, int r35) {
        /*
            Method dump skipped, instructions count: 1657
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.appset.e.x(java.lang.StringBuilder, android.text.SpannableStringBuilder, int, int, java.util.ArrayList, int):void");
    }

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public e(Context context) {
        this.a = 0;
        ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        this.c = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
        this.d = Executors.newSingleThreadExecutor();
        this.b = context;
        scheduledExecutorServiceNewSingleThreadScheduledExecutor.scheduleAtFixedRate(new com.google.android.gms.common.api.internal.w(this, 1), 0L, 86400L, TimeUnit.SECONDS);
    }

    public e(y service, com.quizlet.remote.model.explanations.search.c searchTypeAheadMapper, AbstractC5040y ioDispatcher) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(searchTypeAheadMapper, "searchTypeAheadMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = service;
        this.c = searchTypeAheadMapper;
        this.d = ioDispatcher;
    }

    public e(dagger.internal.a generatePracticeTestsWithTextUseCase, dagger.internal.a generatePracticeTestsWithFileUseCase, dagger.internal.a generatePracticeTestsWithFlashcardSetsUseCase) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(generatePracticeTestsWithTextUseCase, "generatePracticeTestsWithTextUseCase");
        Intrinsics.checkNotNullParameter(generatePracticeTestsWithFileUseCase, "generatePracticeTestsWithFileUseCase");
        Intrinsics.checkNotNullParameter(generatePracticeTestsWithFlashcardSetsUseCase, "generatePracticeTestsWithFlashcardSetsUseCase");
        this.b = generatePracticeTestsWithTextUseCase;
        this.c = generatePracticeTestsWithFileUseCase;
        this.d = generatePracticeTestsWithFlashcardSetsUseCase;
    }

    public e(EventLogger eventLogger, com.quizlet.data.repository.user.a googleAnalyticsLogger, com.quizlet.data.repository.classfolder.e marketingLoggerManager) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(googleAnalyticsLogger, "googleAnalyticsLogger");
        Intrinsics.checkNotNullParameter(marketingLoggerManager, "marketingLoggerManager");
        this.b = eventLogger;
        this.c = googleAnalyticsLogger;
        this.d = marketingLoggerManager;
    }

    public e(androidx.work.impl.model.e getTermsUseCase, com.quizlet.data.repository.widget.b selectedTermUseCase, com.quizlet.data.repository.qclass.c diagramDataUseCase) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(getTermsUseCase, "getTermsUseCase");
        Intrinsics.checkNotNullParameter(selectedTermUseCase, "selectedTermUseCase");
        Intrinsics.checkNotNullParameter(diagramDataUseCase, "diagramDataUseCase");
        this.b = getTermsUseCase;
        this.c = selectedTermUseCase;
        this.d = diagramDataUseCase;
    }

    public e(com.quizlet.data.repository.user.a subFolderFeature, o studyMaterialsUseCase, C0429a folderStudyMaterialMapper) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(subFolderFeature, "subFolderFeature");
        Intrinsics.checkNotNullParameter(studyMaterialsUseCase, "studyMaterialsUseCase");
        Intrinsics.checkNotNullParameter(folderStudyMaterialMapper, "folderStudyMaterialMapper");
        this.b = subFolderFeature;
        this.c = studyMaterialsUseCase;
        this.d = folderStudyMaterialMapper;
    }

    public e(com.quizlet.scandocument.ui.d tooltipState, androidx.work.impl.model.c userProps, com.google.mlkit.common.internal.model.a plusBadgeFeature) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(tooltipState, "tooltipState");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(plusBadgeFeature, "plusBadgeFeature");
        this.b = tooltipState;
        this.c = userProps;
        this.d = plusBadgeFeature;
    }

    public e(InterfaceC4774a service, com.quizlet.remote.model.achievements.d mapper, AbstractC5040y dispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = service;
        this.c = mapper;
        this.d = dispatcher;
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 4:
                List list = Collections.EMPTY_LIST;
                this.b = list;
                this.c = list;
                break;
            case 7:
                this.b = new HashMap();
                this.c = new HashMap();
                this.d = C3319a2.c;
                break;
            default:
                this.b = new WeakHashMap();
                this.c = new WeakHashMap();
                this.d = new WeakHashMap();
                break;
        }
    }

    public e(EnumC5145a alignmentRendering, List plugins) {
        this.a = 20;
        List ignoredTags = B.j("body", "html");
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(plugins, "plugins");
        Intrinsics.checkNotNullParameter(ignoredTags, "ignoredTags");
        this.b = alignmentRendering;
        this.c = plugins;
        this.d = ignoredTags;
    }

    public e(Context context, LocationManager locationManager) {
        this.a = 1;
        this.d = new O();
        this.b = context;
        this.c = locationManager;
    }

    public e(p0 p0Var, ArrayList arrayList, InterfaceC0183w interfaceC0183w) {
        this.a = 2;
        this.d = p0Var;
        this.b = arrayList;
        this.c = interfaceC0183w;
    }

    public e(j jVar, ArrayList arrayList, m mVar) {
        this.a = 5;
        com.bumptech.glide.util.f.c(mVar, "Argument must not be null");
        this.c = mVar;
        com.bumptech.glide.util.f.c(arrayList, "Argument must not be null");
        this.d = arrayList;
        this.b = new i(jVar, mVar);
    }
}

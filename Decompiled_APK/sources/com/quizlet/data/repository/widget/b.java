package com.quizlet.data.repository.widget;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import androidx.camera.core.C0157i;
import androidx.camera.core.impl.utils.futures.c;
import androidx.camera.view.r;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.r0;
import androidx.constraintlayout.core.g;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.V;
import androidx.viewpager.widget.ViewPager;
import com.bumptech.glide.k;
import com.bumptech.glide.load.resource.bitmap.j;
import com.bumptech.glide.load.resource.bitmap.m;
import com.bumptech.glide.load.resource.bitmap.n;
import com.bumptech.glide.load.resource.bitmap.w;
import com.bumptech.glide.request.f;
import com.bumptech.glide.util.e;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.internal.util.o;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.ads.D3;
import com.google.android.gms.internal.ads.zzaqd;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.s7;
import com.google.firebase.messaging.FirebaseMessaging;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.data.model.E0;
import com.quizlet.db.data.caches.UserInfoCache;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes2.dex */
public class b implements c, InterfaceC1062t, n, D3, InterfaceC5182g, h {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0047 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0042 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.quizlet.data.repository.widget.b a(android.content.Context r5) throws java.io.IOException {
        /*
            java.lang.String r0 = "generatefid.lock"
            r1 = 0
            java.io.File r2 = new java.io.File     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            java.io.File r5 = r5.getFilesDir()     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            r2.<init>(r5, r0)     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            java.io.RandomAccessFile r5 = new java.io.RandomAccessFile     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            java.lang.String r0 = "rw"
            r5.<init>(r2, r0)     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            java.nio.channels.FileChannel r5 = r5.getChannel()     // Catch: java.nio.channels.OverlappingFileLockException -> L31 java.lang.Error -> L35 java.io.IOException -> L37
            java.nio.channels.FileLock r0 = r5.lock()     // Catch: java.nio.channels.OverlappingFileLockException -> L2a java.lang.Error -> L2d java.io.IOException -> L2f
            com.quizlet.data.repository.widget.b r2 = new com.quizlet.data.repository.widget.b     // Catch: java.nio.channels.OverlappingFileLockException -> L24 java.lang.Error -> L26 java.io.IOException -> L28
            r3 = 12
            r4 = 0
            r2.<init>(r5, r4, r0, r3)     // Catch: java.nio.channels.OverlappingFileLockException -> L24 java.lang.Error -> L26 java.io.IOException -> L28
            return r2
        L24:
            r2 = move-exception
            goto L39
        L26:
            r2 = move-exception
            goto L39
        L28:
            r2 = move-exception
            goto L39
        L2a:
            r2 = move-exception
        L2b:
            r0 = r1
            goto L39
        L2d:
            r2 = move-exception
            goto L2b
        L2f:
            r2 = move-exception
            goto L2b
        L31:
            r2 = move-exception
        L32:
            r5 = r1
            r0 = r5
            goto L39
        L35:
            r2 = move-exception
            goto L32
        L37:
            r2 = move-exception
            goto L32
        L39:
            java.lang.String r3 = "CrossProcessLock"
            java.lang.String r4 = "encountered error while creating and acquiring the lock, ignoring"
            android.util.Log.e(r3, r4, r2)
            if (r0 == 0) goto L45
            r0.release()     // Catch: java.io.IOException -> L45
        L45:
            if (r5 == 0) goto L4a
            r5.close()     // Catch: java.io.IOException -> L4a
        L4a:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.widget.b.a(android.content.Context):com.quizlet.data.repository.widget.b");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 14:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                AbstractC3762x6.b((org.slf4j.b) this.b, e, (String) this.c);
                return p.d(e);
            case 18:
                Throwable e2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.folderset.c) this.b).d).h("Network Error", e2);
                return p.f((List) this.c);
            case 19:
                Long userId = (Long) obj;
                Intrinsics.checkNotNullParameter(userId, "userId");
                com.quizlet.explanations.textbook.exercisedetail.viewmodel.c cVar = (com.quizlet.explanations.textbook.exercisedetail.viewmodel.c) this.b;
                return cVar.h.u(userId.longValue(), (E0) this.c, cVar.c);
            case EventType.WINDOW_STATE /* 22 */:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                List list = (List) this.b;
                Intrinsics.d(list);
                return AbstractC3771z.c((com.quizlet.local.ormlite.models.folder.a) ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c, list);
            default:
                String imageUrl = (String) obj;
                Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
                s sVar = (s) this.b;
                return ((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) sVar.c).a(((com.quizlet.quizletandroid.data.management.a) this.c).b.a(imageUrl, com.quizlet.qutils.data.offline.b.c));
        }
    }

    public void b(E e, boolean z) {
        com.quizlet.data.repository.searchexplanations.c cVar = (com.quizlet.data.repository.searchexplanations.c) this.c;
        com.quizlet.data.repository.searchexplanations.c cVar2 = (com.quizlet.data.repository.searchexplanations.c) this.b;
        if (z) {
            cVar2.b(e);
            cVar.b(e);
        } else {
            if (((r0) cVar2.c).contains(e)) {
                return;
            }
            cVar.b(e);
        }
    }

    @Override // com.bumptech.glide.load.resource.bitmap.n
    public void c(Bitmap bitmap, com.bumptech.glide.load.engine.bitmap_recycle.a aVar) throws IOException {
        IOException iOException = ((e) this.c).b;
        if (iOException != null) {
            if (bitmap == null) {
                throw iOException;
            }
            aVar.b(bitmap);
            throw iOException;
        }
    }

    public void d() {
        f fVar = (f) this.c;
        fVar.getClass();
        fVar.s(m.c, new j());
    }

    public boolean e(E e, boolean z) {
        boolean zContains = ((r0) ((com.quizlet.data.repository.searchexplanations.c) this.b).c).contains(e);
        return z ? zContains : zContains || ((r0) ((com.quizlet.data.repository.searchexplanations.c) this.c).c).contains(e);
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        OTLogger.c("GoogleVendorHelper", 6, "Google Vendor list Api Failed :  " + th.getMessage());
        com.google.firebase.tracing.a aVar = (com.google.firebase.tracing.a) this.b;
        if (aVar != null) {
            aVar.onCompletion(false);
        }
    }

    public void g(String str) {
        if (Log.isLoggable((String) this.b, 3)) {
            t(str);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r11v2, types: [java.lang.Iterable, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r10, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r9 = this;
            boolean r0 = r12 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.b
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.b r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.b r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.b
            r0.<init>(r9, r12)
        L18:
            java.lang.Object r12 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r12)
            kotlin.r r12 = (kotlin.r) r12
            java.lang.Object r10 = r12.a
            goto L43
        L2b:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r0.l = r3
            java.lang.Object r12 = r9.c
            com.quizlet.data.interactor.achievements.f r12 = (com.quizlet.data.interactor.achievements.f) r12
            java.lang.Object r10 = r12.l(r10, r0)
            if (r10 != r1) goto L43
            return r1
        L43:
            kotlin.p r11 = kotlin.r.b
            boolean r11 = r10 instanceof kotlin.q
            if (r11 != 0) goto L82
            com.quizlet.data.model.L r10 = (com.quizlet.data.model.L) r10
            java.lang.Object r11 = r10.a
            java.util.ArrayList r12 = new java.util.ArrayList
            r0 = 10
            int r0 = kotlin.collections.C.q(r11, r0)
            r12.<init>(r0)
            java.util.Iterator r11 = r11.iterator()
        L5c:
            boolean r0 = r11.hasNext()
            if (r0 == 0) goto L81
            java.lang.Object r0 = r11.next()
            com.quizlet.data.model.Course r0 = (com.quizlet.data.model.Course) r0
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r1 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c
            long r2 = r0.a
            java.lang.String r5 = r0.e
            java.lang.String r0 = r0.b
            if (r0 != 0) goto L74
            r4 = r5
            goto L75
        L74:
            r4 = r0
        L75:
            java.lang.String r7 = r10.b
            r6 = 0
            r8 = 24
            r1.<init>(r2, r4, r5, r6, r7, r8)
            r12.add(r1)
            goto L5c
        L81:
            return r12
        L82:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.widget.b.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.bumptech.glide.load.resource.bitmap.n
    public void i() {
        w wVar = (w) this.b;
        synchronized (wVar) {
            wVar.c = wVar.a.length;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(kotlin.coroutines.jvm.internal.c r11) {
        /*
            r10 = this;
            boolean r0 = r11 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.c
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.c r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.c r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.c
            r0.<init>(r10, r11)
        L18:
            java.lang.Object r11 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r11)
            kotlin.r r11 = (kotlin.r) r11
            java.lang.Object r11 = r11.a
            goto L43
        L2b:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            r0.l = r3
            java.lang.Object r11 = r10.b
            com.quizlet.data.interactor.achievements.f r11 = (com.quizlet.data.interactor.achievements.f) r11
            java.lang.Object r11 = r11.k(r0)
            if (r11 != r1) goto L43
            return r1
        L43:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r11 instanceof kotlin.q
            if (r0 != 0) goto L92
            com.quizlet.data.model.x1 r11 = (com.quizlet.data.model.C4180x1) r11
            java.util.List r0 = r11.a
            java.util.ArrayList r1 = new java.util.ArrayList
            r2 = 10
            int r2 = kotlin.collections.C.q(r0, r2)
            r1.<init>(r2)
            java.util.Iterator r0 = r0.iterator()
        L5c:
            boolean r2 = r0.hasNext()
            if (r2 == 0) goto L91
            java.lang.Object r2 = r0.next()
            com.quizlet.data.model.School r2 = (com.quizlet.data.model.School) r2
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r3 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e
            long r4 = r2.a
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>()
            java.lang.String r7 = r2.b
            r6.append(r7)
            java.lang.String r7 = ", "
            r6.append(r7)
            java.lang.String r7 = r2.j
            r6.append(r7)
            java.lang.String r7 = r6.toString()
            java.lang.String r6 = r2.i
            java.lang.String r8 = r11.b
            r9 = 24
            r3.<init>(r4, r6, r7, r8, r9)
            r1.add(r3)
            goto L5c
        L91:
            return r1
        L92:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.widget.b.j(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, K k) {
        com.onetrust.otpublishers.headless.Internal.Helper.a aVar = (com.onetrust.otpublishers.headless.Internal.Helper.a) this.c;
        StringBuilder sb = new StringBuilder("Google Vendor list Api Success : ");
        Object obj = k.b;
        sb.append((String) obj);
        OTLogger.c("GoogleVendorHelper", 4, sb.toString());
        H h = k.a;
        StringBuilder sb2 = new StringBuilder("Google vendor api response time : ");
        long j = h.l;
        sb2.append(j);
        sb2.append(",");
        long j2 = h.k;
        sb2.append(j2);
        OTLogger.c("GoogleVendorHelper", 2, sb2.toString());
        long j3 = j - j2;
        OTLogger.c("OneTrust", 3, String.format("%s %d.%d s", "Time taken for Google Vendor data fetch: ", Long.valueOf(TimeUnit.MILLISECONDS.toSeconds(j3)), Long.valueOf(j3 % 1000)));
        com.onetrust.otpublishers.headless.Internal.Helper.a.b(aVar.a, (String) obj);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(int r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.quizlet.data.repository.widget.a
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.data.repository.widget.a r0 = (com.quizlet.data.repository.widget.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.widget.a r0 = new com.quizlet.data.repository.widget.a
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.repository.widget.b r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7c
        L29:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r8.c
            com.quizlet.local.cache.caches.c r10 = (com.quizlet.local.cache.caches.c) r10
            com.quizlet.local.cache.e r2 = r10.a
            r2.getClass()
            kotlin.Unit r4 = kotlin.Unit.a
            java.lang.Object r2 = r2.get(r4)
            com.quizlet.data.model.x2 r2 = (com.quizlet.data.model.x2) r2
            if (r2 == 0) goto L53
            long r4 = r10.b
            long r6 = com.quizlet.time.b.a()
            int r10 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r10 > 0) goto L52
            goto L53
        L52:
            return r2
        L53:
            r0.j = r8
            r0.m = r3
            java.lang.Object r10 = r8.b
            com.google.android.gms.ads.internal.client.n r10 = (com.google.android.gms.ads.internal.client.C1608n) r10
            java.lang.Object r2 = r10.d
            com.quizlet.db.data.caches.UserInfoCache r2 = (com.quizlet.db.data.caches.UserInfoCache) r2
            boolean r2 = r2.b()
            if (r2 != 0) goto L69
            com.quizlet.data.model.z2 r9 = com.quizlet.data.model.z2.a
        L67:
            r10 = r9
            goto L78
        L69:
            com.quizlet.remote.model.widget.b r2 = new com.quizlet.remote.model.widget.b
            r3 = 0
            r2.<init>(r10, r9, r3)
            java.lang.Object r9 = r10.c
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r2, r0)
            goto L67
        L78:
            if (r10 != r1) goto L7b
            return r1
        L7b:
            r9 = r8
        L7c:
            com.quizlet.data.model.x2 r10 = (com.quizlet.data.model.x2) r10
            boolean r0 = r10.a()
            if (r0 == 0) goto L9b
            java.lang.Object r9 = r9.c
            com.quizlet.local.cache.caches.c r9 = (com.quizlet.local.cache.caches.c) r9
            com.quizlet.local.cache.e r0 = r9.a
            r0.getClass()
            kotlin.Unit r1 = kotlin.Unit.a
            r0.a(r1, r10)
            long r0 = com.quizlet.time.b.a()
            r2 = 600(0x258, double:2.964E-321)
            long r0 = r0 + r2
            r9.b = r0
        L9b:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.widget.b.l(int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Object m(com.airbnb.lottie.value.b bVar) {
        return (com.airbnb.lottie.E) this.c;
    }

    public Object n(float f, float f2, Object obj, Object obj2, float f3, float f4, float f5) {
        com.airbnb.lottie.value.b bVar = (com.airbnb.lottie.value.b) this.b;
        bVar.a = f;
        bVar.b = f2;
        bVar.f = obj;
        bVar.g = obj2;
        bVar.c = f3;
        bVar.d = f4;
        bVar.e = f5;
        return m(bVar);
    }

    public void o(ImageView imageView) {
        k kVar = (k) this.b;
        kVar.b((f) this.c);
        try {
            kVar.z(imageView);
        } catch (IllegalArgumentException e) {
            timber.log.c.a(e);
            imageView.setImageDrawable(null);
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        throw new IllegalStateException("SurfaceReleaseFuture did not complete nicely.", th);
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        AbstractC3242q6.h("Unexpected result from SurfaceRequest. Surface was provided twice.", ((C0157i) obj).a != 3);
        AbstractC3053s1.f(3, "TextureViewImpl");
        ((SurfaceTexture) this.b).release();
        androidx.camera.view.s sVar = ((r) this.c).a;
        if (sVar.j != null) {
            sVar.j = null;
        }
    }

    public void p(ImageView imageView, com.quizlet.infra.legacysyncengine.tasks.parse.b bVar, com.quizlet.qutils.rx.b bVar2) {
        k kVar = (k) this.b;
        kVar.b((f) this.c);
        try {
            kVar.B(new com.onetrust.otpublishers.headless.UI.extensions.a(1, bVar2, bVar)).z(imageView);
        } catch (IllegalArgumentException e) {
            timber.log.c.a(e);
            imageView.setImageDrawable(null);
            bVar2.run();
        }
    }

    public boolean q() {
        return !(((r0) ((com.quizlet.data.repository.searchexplanations.c) this.c).c).isEmpty() && ((r0) ((com.quizlet.data.repository.searchexplanations.c) this.b).c).isEmpty());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0187  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /* JADX WARN: Type inference failed for: r15v5, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r17v0 */
    /* JADX WARN: Type inference failed for: r17v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r17v2 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:37:0x0129 -> B:38:0x0134). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object r(com.quizlet.remote.model.notes.StudyNoteModel r30, kotlin.coroutines.jvm.internal.c r31) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 394
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.widget.b.r(com.quizlet.remote.model.notes.StudyNoteModel, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void s() throws IOException {
        try {
            ((FileLock) this.c).release();
            ((FileChannel) this.b).close();
        } catch (IOException e) {
            Log.e("CrossProcessLock", "encountered error while releasing, ignoring", e);
        }
    }

    public String t(String str) {
        String str2 = (String) this.c;
        return str2 == null ? str : str2.concat(str);
    }

    public String toString() {
        switch (this.a) {
            case 4:
                String string = "[ ";
                if (((g) this.b) != null) {
                    for (int i = 0; i < 9; i++) {
                        StringBuilder sbU = d0.u(string);
                        sbU.append(((g) this.b).h[i]);
                        sbU.append(" ");
                        string = sbU.toString();
                    }
                }
                StringBuilder sbX = android.support.v4.media.session.a.x(string, "] ");
                sbX.append((g) this.b);
                return sbX.toString();
            default:
                return super.toString();
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        D0 d0J = V.j(d0, view);
        if (d0J.a.o()) {
            return d0J;
        }
        int iB = d0J.b();
        Rect rect = (Rect) this.b;
        rect.left = iB;
        rect.top = d0J.d();
        rect.right = d0J.c();
        rect.bottom = d0J.a();
        ViewPager viewPager = (ViewPager) this.c;
        int childCount = viewPager.getChildCount();
        for (int i = 0; i < childCount; i++) {
            D0 d0B = V.b(d0J, viewPager.getChildAt(i));
            rect.left = Math.min(d0B.b(), rect.left);
            rect.top = Math.min(d0B.d(), rect.top);
            rect.right = Math.min(d0B.c(), rect.right);
            rect.bottom = Math.min(d0B.a(), rect.bottom);
        }
        return d0J.f(rect.left, rect.top, rect.right, rect.bottom);
    }

    @Override // com.google.android.gms.internal.ads.D3
    public void x(zzaqd zzaqdVar) {
        i.h("Failed to load URL: " + ((String) this.b) + "\n" + zzaqdVar.toString());
        ((o) this.c).c(null);
    }

    public /* synthetic */ b(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public b(com.quizlet.data.interactor.folderwithcreator.m mVar) {
        this.a = 10;
        this.c = new C3();
        this.b = mVar;
        s7.b();
    }

    public b(String str, String str2) {
        this.a = 9;
        Object[] objArr = {str, 23};
        if (str.length() <= 23) {
            this.b = str;
            this.c = (str2 == null || str2.length() <= 0) ? null : str2;
            return;
        }
        throw new IllegalArgumentException(String.format("tag \"%s\" is longer than the %d character maximum", objArr));
    }

    public b(com.quizlet.data.interactor.achievements.f schoolSuggestionsUseCase, com.quizlet.data.interactor.achievements.f courseSuggestionUseCase) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(schoolSuggestionsUseCase, "schoolSuggestionsUseCase");
        Intrinsics.checkNotNullParameter(courseSuggestionUseCase, "courseSuggestionUseCase");
        this.b = schoolSuggestionsUseCase;
        this.c = courseSuggestionUseCase;
    }

    public b(com.quizlet.quizletandroid.ui.group.data.b dataSourceFactory) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(dataSourceFactory, "dataSourceFactory");
        this.b = dataSourceFactory;
    }

    public b(C1608n remote, com.quizlet.local.cache.caches.c cache) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(cache, "cache");
        this.b = remote;
        this.c = cache;
    }

    public b(com.google.android.gms.internal.p000authapi.b googleOneTapClient, com.google.android.gms.auth.api.signin.a googleSignInClient) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(googleOneTapClient, "googleOneTapClient");
        Intrinsics.checkNotNullParameter(googleSignInClient, "googleSignInClient");
        this.b = googleOneTapClient;
        this.c = googleSignInClient;
    }

    public b(com.quizlet.data.repository.folderset.c repository, androidx.work.impl.model.c dispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public b(com.quizlet.data.repository.selectedterm.f repository, UserInfoCache userInfoCache) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = repository;
        this.c = userInfoCache;
    }

    public b(com.quizlet.login.authentication.login.a dataSource, com.quizlet.quizletandroid.ui.folder.logging.a mapper) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dataSource;
        this.c = mapper;
    }

    public b(com.quizlet.data.repository.explanations.textbook.a repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public b(com.quizlet.data.repository.user.e userRepository, com.quizlet.quizletandroid.k artifactMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(userRepository, "userRepository");
        Intrinsics.checkNotNullParameter(artifactMapper, "artifactMapper");
        this.b = userRepository;
        this.c = artifactMapper;
    }

    public b(com.quizlet.data.interactor.course.a brazeEventLogger, UserInfoCache userInfoCache) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(brazeEventLogger, "brazeEventLogger");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = brazeEventLogger;
        this.c = userInfoCache;
    }

    public b(FirebaseMessaging firebaseMessaging, io.reactivex.rxjava3.core.o scheduler) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(firebaseMessaging, "firebaseMessaging");
        Intrinsics.checkNotNullParameter(scheduler, "scheduler");
        this.b = firebaseMessaging;
        this.c = scheduler;
    }

    public b(k kVar) {
        this.a = 26;
        this.c = new f();
        this.b = kVar;
    }

    public b(com.airbnb.lottie.E e) {
        this.a = 6;
        this.b = new com.airbnb.lottie.value.b();
        this.c = e;
    }

    public b(androidx.constraintlayout.core.f fVar) {
        this.a = 4;
        this.c = fVar;
    }

    public b(int i) {
        this.a = i;
        switch (i) {
            case 6:
                this.b = new com.airbnb.lottie.value.b();
                this.c = null;
                break;
            case 11:
                break;
            default:
                this.b = new com.quizlet.data.repository.searchexplanations.c();
                this.c = new com.quizlet.data.repository.searchexplanations.c();
                break;
        }
    }

    public b(Handler handler) {
        this.a = 1;
        this.b = new HashMap();
        this.c = handler;
    }

    public b(ViewPager viewPager) {
        this.a = 5;
        this.c = viewPager;
        this.b = new Rect();
    }
}

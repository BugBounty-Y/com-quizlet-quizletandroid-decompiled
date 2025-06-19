package com.quizlet.data.repository.classfolder;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.util.AttributeSet;
import android.util.TypedValue;
import androidx.appcompat.widget.C0112u;
import androidx.appcompat.widget.U;
import androidx.compose.animation.d0;
import androidx.compose.runtime.internal.k;
import androidx.compose.runtime.internal.l;
import androidx.compose.ui.node.V;
import assistantMode.types.w;
import com.android.billingclient.api.s;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.resource.bitmap.C1541d;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.facebook.appevents.g;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.mlkit_vision_common.C3443e;
import com.google.android.gms.measurement.internal.K;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.gms.measurement.internal.t1;
import com.google.firebase.remoteconfig.internal.j;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.eventlogger.features.pushnotifications.PushNotificationLogger;
import com.quizlet.infra.legacysyncengine.tasks.parse.f;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class e implements com.bumptech.glide.load.resource.transcode.b, com.google.firebase.encoders.config.a, K, h {
    public static Boolean e;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public e(r1 r1Var, String str, t1 t1Var) {
        this.a = 8;
        this.b = str;
        this.c = t1Var;
        this.d = r1Var;
    }

    public static e l(Context context, AttributeSet attributeSet, int[] iArr) {
        return new e(context, context.obtainStyledAttributes(attributeSet, iArr));
    }

    public static e m(Context context, AttributeSet attributeSet, int[] iArr, int i) {
        return new e(context, context.obtainStyledAttributes(attributeSet, iArr, i, 0));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0025 A[Catch: all -> 0x000d, TRY_ENTER, TryCatch #0 {all -> 0x000d, blocks: (B:4:0x000a, B:22:0x006b, B:25:0x008f, B:14:0x0025, B:16:0x004d, B:18:0x0058, B:20:0x0063, B:21:0x0067), top: B:30:0x000a }] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0067 A[Catch: all -> 0x000d, TryCatch #0 {all -> 0x000d, blocks: (B:4:0x000a, B:22:0x006b, B:25:0x008f, B:14:0x0025, B:16:0x004d, B:18:0x0058, B:20:0x0063, B:21:0x0067), top: B:30:0x000a }] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x008e  */
    /* JADX WARN: Type inference failed for: r9v8, types: [java.lang.String] */
    @Override // com.google.android.gms.measurement.internal.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void a(java.lang.String r6, int r7, java.io.IOException r8, byte[] r9, java.util.Map r10) {
        /*
            r5 = this;
            java.lang.Object r6 = r5.d
            com.google.android.gms.measurement.internal.r1 r6 = (com.google.android.gms.measurement.internal.r1) r6
            com.google.android.gms.measurement.internal.Z.l(r6)
            r10 = 0
            if (r9 != 0) goto L10
            byte[] r9 = new byte[r10]     // Catch: java.lang.Throwable -> Ld
            goto L10
        Ld:
            r7 = move-exception
            goto La7
        L10:
            java.lang.Object r0 = r5.c
            com.google.android.gms.measurement.internal.t1 r0 = (com.google.android.gms.measurement.internal.t1) r0
            r1 = 200(0xc8, float:2.8E-43)
            long r2 = r0.a
            java.lang.Object r0 = r5.b
            java.lang.String r0 = (java.lang.String) r0
            if (r7 == r1) goto L23
            r1 = 204(0xcc, float:2.86E-43)
            if (r7 != r1) goto L6b
            r7 = r1
        L23:
            if (r8 != 0) goto L6b
            com.google.android.gms.measurement.internal.j r8 = r6.c     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.r1.L(r8)     // Catch: java.lang.Throwable -> Ld
            java.lang.Long r9 = java.lang.Long.valueOf(r2)     // Catch: java.lang.Throwable -> Ld
            r8.g0(r9)     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.I r8 = r6.c()     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.internal.ads.Ka r8 = r8.o     // Catch: java.lang.Throwable -> Ld
            java.lang.String r9 = "Successfully uploaded batch from upload queue. appId, status"
            java.lang.Integer r7 = java.lang.Integer.valueOf(r7)     // Catch: java.lang.Throwable -> Ld
            r8.h(r9, r0, r7)     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.e r7 = r6.h0()     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.s r8 = com.google.android.gms.measurement.internal.AbstractC3893t.M0     // Catch: java.lang.Throwable -> Ld
            r9 = 0
            boolean r7 = r7.f0(r9, r8)     // Catch: java.lang.Throwable -> Ld
            if (r7 == 0) goto L67
            com.google.android.gms.measurement.internal.M r7 = r6.b     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.r1.L(r7)     // Catch: java.lang.Throwable -> Ld
            boolean r7 = r7.r0()     // Catch: java.lang.Throwable -> Ld
            if (r7 == 0) goto L67
            com.google.android.gms.measurement.internal.j r7 = r6.c     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.r1.L(r7)     // Catch: java.lang.Throwable -> Ld
            boolean r7 = r7.r0(r0)     // Catch: java.lang.Throwable -> Ld
            if (r7 == 0) goto L67
            r6.Z(r0)     // Catch: java.lang.Throwable -> Ld
            goto La1
        L67:
            r6.F()     // Catch: java.lang.Throwable -> Ld
            goto La1
        L6b:
            java.lang.String r1 = new java.lang.String     // Catch: java.lang.Throwable -> Ld
            java.nio.charset.Charset r4 = java.nio.charset.StandardCharsets.UTF_8     // Catch: java.lang.Throwable -> Ld
            r1.<init>(r9, r4)     // Catch: java.lang.Throwable -> Ld
            int r9 = r1.length()     // Catch: java.lang.Throwable -> Ld
            r4 = 32
            int r9 = java.lang.Math.min(r4, r9)     // Catch: java.lang.Throwable -> Ld
            java.lang.String r9 = r1.substring(r10, r9)     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.I r1 = r6.c()     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.internal.ads.Ka r1 = r1.l     // Catch: java.lang.Throwable -> Ld
            java.lang.String r4 = "Network upload failed. Will retry later. appId, status, error"
            java.lang.Integer r7 = java.lang.Integer.valueOf(r7)     // Catch: java.lang.Throwable -> Ld
            if (r8 != 0) goto L8f
            r8 = r9
        L8f:
            r1.i(r4, r0, r7, r8)     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.j r7 = r6.c     // Catch: java.lang.Throwable -> Ld
            com.google.android.gms.measurement.internal.r1.L(r7)     // Catch: java.lang.Throwable -> Ld
            java.lang.Long r8 = java.lang.Long.valueOf(r2)     // Catch: java.lang.Throwable -> Ld
            r7.j0(r8)     // Catch: java.lang.Throwable -> Ld
            r6.F()     // Catch: java.lang.Throwable -> Ld
        La1:
            r6.u = r10
            r6.C()
            return
        La7:
            r6.u = r10
            r6.C()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.classfolder.e.a(java.lang.String, int, java.io.IOException, byte[], java.util.Map):void");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 14:
                Boolean audioResults = (Boolean) obj;
                Intrinsics.checkNotNullParameter(audioResults, "audioResults");
                timber.log.a aVar = timber.log.c.a;
                com.quizlet.quizletandroid.data.management.a aVar2 = (com.quizlet.quizletandroid.data.management.a) this.b;
                aVar.a(d0.o(aVar2.a.getId(), "Asset collection for ", " :"), new Object[0]);
                aVar.a("\t%s of %s audio files successfully downloaded: %s", String.valueOf(((List) this.c).size()), String.valueOf(((HashSet) this.d).size()), String.valueOf(audioResults.booleanValue()));
                return aVar2;
            default:
                Boolean canShareAll = (Boolean) obj;
                Intrinsics.checkNotNullParameter(canShareAll, "canShareAll");
                return canShareAll.booleanValue() ? p.f(com.quizlet.features.infra.basestudy.data.models.shareset.a.a) : ((com.google.android.material.shape.e) ((com.quizlet.data.repository.activitycenter.b) this.b).c).v((androidx.work.impl.model.c) this.c, (com.quizlet.infra.legacysyncengine.features.properties.d) this.d).g(com.quizlet.quizletandroid.managers.share.a.a);
        }
    }

    public float b(androidx.constraintlayout.core.parser.c cVar) {
        if (!(cVar instanceof androidx.constraintlayout.core.parser.h)) {
            return cVar instanceof androidx.constraintlayout.core.parser.e ? ((androidx.constraintlayout.core.parser.e) cVar).e() : DefinitionKt.NO_Float_VALUE;
        }
        String strC = ((androidx.constraintlayout.core.parser.h) cVar).c();
        HashMap map = (HashMap) this.c;
        if (map.containsKey(strC)) {
            return ((androidx.constraintlayout.core.state.d) map.get(strC)).value();
        }
        HashMap map2 = (HashMap) this.b;
        return map2.containsKey(strC) ? ((Integer) map2.get(strC)).floatValue() : DefinitionKt.NO_Float_VALUE;
    }

    public Object c() {
        long jC = androidx.compose.runtime.internal.e.c();
        if (jC == l.a) {
            return this.d;
        }
        k kVar = (k) ((AtomicReference) this.b).get();
        int iA = kVar.a(jC);
        if (iA >= 0) {
            return kVar.c[iA];
        }
        return null;
    }

    @Override // com.bumptech.glide.load.resource.transcode.b
    public v d(v vVar, com.bumptech.glide.load.h hVar) {
        Drawable drawable = (Drawable) vVar.get();
        if (drawable instanceof BitmapDrawable) {
            return ((s) this.c).d(C1541d.d(((BitmapDrawable) drawable).getBitmap(), (com.bumptech.glide.load.engine.bitmap_recycle.a) this.b), hVar);
        }
        if (drawable instanceof com.bumptech.glide.load.resource.gif.b) {
            return ((com.bumptech.glide.load.resource.transcode.d) this.d).d(vVar, hVar);
        }
        return null;
    }

    public ColorStateList e(int i) {
        int resourceId;
        ColorStateList colorStateListC;
        TypedArray typedArray = (TypedArray) this.c;
        return (!typedArray.hasValue(i) || (resourceId = typedArray.getResourceId(i, 0)) == 0 || (colorStateListC = androidx.core.content.c.c((Context) this.b, resourceId)) == null) ? typedArray.getColorStateList(i) : colorStateListC;
    }

    public Drawable f(int i) {
        int resourceId;
        TypedArray typedArray = (TypedArray) this.c;
        return (!typedArray.hasValue(i) || (resourceId = typedArray.getResourceId(i, 0)) == 0) ? typedArray.getDrawable(i) : g.f((Context) this.b, resourceId);
    }

    @Override // com.google.firebase.encoders.config.a
    public /* bridge */ /* synthetic */ com.google.firebase.encoders.config.a g(Class cls, com.google.firebase.encoders.c cVar) {
        ((HashMap) this.b).put(cls, cVar);
        ((HashMap) this.c).remove(cls);
        return this;
    }

    public Drawable h(int i) {
        int resourceId;
        Drawable drawableD;
        if (!((TypedArray) this.c).hasValue(i) || (resourceId = ((TypedArray) this.c).getResourceId(i, 0)) == 0) {
            return null;
        }
        C0112u c0112uA = C0112u.a();
        Context context = (Context) this.b;
        synchronized (c0112uA) {
            drawableD = c0112uA.a.d(context, resourceId, true);
        }
        return drawableD;
    }

    public Typeface i(int i, int i2, U u) {
        int resourceId = ((TypedArray) this.c).getResourceId(i, 0);
        if (resourceId == 0) {
            return null;
        }
        if (((TypedValue) this.d) == null) {
            this.d = new TypedValue();
        }
        TypedValue typedValue = (TypedValue) this.d;
        ThreadLocal threadLocal = androidx.core.content.res.k.a;
        Context context = (Context) this.b;
        if (context.isRestricted()) {
            return null;
        }
        return androidx.core.content.res.k.b(context, resourceId, typedValue, i2, u, true, false);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r7v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r7v5, types: [java.util.ArrayList] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(long r6, com.quizlet.data.model.J0 r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r5 = this;
            boolean r0 = r9 instanceof com.quizlet.remote.model.term.b
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.remote.model.term.b r0 = (com.quizlet.remote.model.term.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.term.b r0 = new com.quizlet.remote.model.term.b
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L36
            if (r2 != r4) goto L2e
            com.quizlet.data.repository.classfolder.e r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r7 = r9.a
            goto L51
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            if (r8 == 0) goto L40
            com.quizlet.remote.model.base.PagingInfo r8 = com.quizlet.remote.model.base.b.b(r8)
            goto L41
        L40:
            r8 = r3
        L41:
            r0.j = r5
            r0.m = r4
            java.lang.Object r9 = r5.b
            com.quizlet.quizletandroid.ui.common.ads.c r9 = (com.quizlet.quizletandroid.ui.common.ads.C4636c) r9
            java.lang.Object r7 = r9.c(r6, r8, r0)
            if (r7 != r1) goto L50
            return r1
        L50:
            r6 = r5
        L51:
            kotlin.p r8 = kotlin.r.b
            boolean r8 = r7 instanceof kotlin.q
            if (r8 != 0) goto La4
            com.quizlet.remote.model.term.TermResponse r7 = (com.quizlet.remote.model.term.TermResponse) r7
            com.quizlet.remote.model.base.PagingInfo r8 = r7.a
            if (r8 == 0) goto L63
            java.lang.Object r9 = r6.d
            com.quizlet.data.model.J0 r3 = com.quizlet.remote.model.base.b.a(r8)
        L63:
            java.lang.Object r6 = r6.c
            com.quizlet.quizletandroid.ui.setcreation.adapters.a r6 = (com.quizlet.quizletandroid.ui.setcreation.adapters.a) r6
            java.lang.String r8 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r8)
            java.lang.String r8 = "mapper"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r8)
            com.quizlet.remote.model.term.TermModels r6 = r7.d
            if (r6 == 0) goto L9c
            java.util.List r6 = r6.a
            if (r6 == 0) goto L9c
            java.util.ArrayList r7 = new java.util.ArrayList
            r8 = 10
            int r8 = kotlin.collections.C.q(r6, r8)
            r7.<init>(r8)
            java.util.Iterator r6 = r6.iterator()
        L88:
            boolean r8 = r6.hasNext()
            if (r8 == 0) goto L9e
            java.lang.Object r8 = r6.next()
            com.quizlet.remote.model.term.RemoteTerm r8 = (com.quizlet.remote.model.term.RemoteTerm) r8
            com.quizlet.data.model.i2 r8 = com.quizlet.quizletandroid.ui.setcreation.adapters.a.b(r8)
            r7.add(r8)
            goto L88
        L9c:
            kotlin.collections.K r7 = kotlin.collections.K.a
        L9e:
            com.quizlet.data.model.N r6 = new com.quizlet.data.model.N
            r6.<init>(r7, r3)
            return r6
        La4:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.classfolder.e.j(long, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public i k() {
        if (((IdMappedQuery) this.b).getAnyFilterValueNegative()) {
            return i.p(new com.quizlet.infra.legacysyncengine.net.request.c(new ArrayList()));
        }
        J jQ = new io.reactivex.rxjava3.internal.operators.maybe.h(0, new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.activitycenter.a(this, 2), 4).m(new com.google.android.material.search.a(this, 29), SubsamplingScaleImageView.TILE_SIZE_AUTO).x(16), new com.quizlet.infra.legacysyncengine.models.serializers.a(3)).g().q(new com.quizlet.infra.legacysyncengine.models.serializers.a(4));
        com.quizlet.billing.subscriptions.a aVar = new com.quizlet.billing.subscriptions.a(this, 9);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        C c = new C(jQ, aVar, bVar);
        com.quizlet.eventlogger.e eVar = new com.quizlet.eventlogger.e(this, 14);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        return new B(c, gVar, gVar, bVar, eVar);
    }

    public void n() {
        ((TypedArray) this.c).recycle();
    }

    public i o(Integer num, String str) {
        int iIntValue = num.intValue();
        V v = (V) this.d;
        com.squareup.otto.c cVar = (com.squareup.otto.c) v.g;
        com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) v.f;
        com.quizlet.infra.legacysyncengine.net.request.d dVar = new com.quizlet.infra.legacysyncengine.net.request.d((IdMappedQuery) this.b, iIntValue, str, (ExecutionRouter) v.c, (androidx.work.impl.model.c) v.d, (f) v.e, sVar, cVar, (DatabaseHelper) v.h);
        return new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.activitycenter.a(dVar, 3), 4).e(new com.quizlet.infra.legacysyncengine.net.request.a(dVar, 0)).g(new com.quizlet.infra.legacysyncengine.net.request.a(dVar, 1)).m();
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    public void p(Function0 function0) {
        Boolean bool = e;
        if (bool != null) {
            if (bool.booleanValue()) {
                function0.invoke();
                return;
            }
            return;
        }
        ((AtomicReference) this.d).dispose();
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(0, new io.reactivex.rxjava3.internal.operators.single.d(((androidx.work.impl.model.c) this.b).u().g(com.quizlet.analytics.marketing.c.a), com.quizlet.analytics.marketing.d.a, 2), com.quizlet.analytics.marketing.c.b);
        Intrinsics.checkNotNullExpressionValue(hVar, "filter(...)");
        io.reactivex.rxjava3.internal.operators.completable.l lVar = new io.reactivex.rxjava3.internal.operators.completable.l(new com.quizlet.analytics.marketing.e(function0, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        hVar.e(lVar);
        this.d = lVar;
    }

    public void q(Object obj) {
        long jC = androidx.compose.runtime.internal.e.c();
        if (jC == l.a) {
            this.d = obj;
            return;
        }
        synchronized (this.c) {
            k kVar = (k) ((AtomicReference) this.b).get();
            int iA = kVar.a(jC);
            if (iA >= 0) {
                kVar.c[iA] = obj;
            } else {
                ((AtomicReference) this.b).set(kVar.b(jC, obj));
                Unit unit = Unit.a;
            }
        }
    }

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public e(Context context, VersionInfoParcel versionInfoParcel) {
        this.a = 6;
        this.b = context;
        this.c = context.getPackageName();
        this.d = versionInfoParcel.a;
    }

    public e(C4636c dataSource, com.quizlet.quizletandroid.ui.setcreation.adapters.a mapper, com.quizlet.remote.model.base.b pagingInfoMapper) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(pagingInfoMapper, "pagingInfoMapper");
        this.b = dataSource;
        this.c = mapper;
        this.d = pagingInfoMapper;
    }

    public e(Context context, AudioAttributes audioAttributes, AudioManager audioManager) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(audioAttributes, "audioAttributes");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        this.b = context;
        this.c = audioAttributes;
        this.d = audioManager;
    }

    public e(com.quizlet.remote.service.k service, com.quizlet.quizletandroid.ui.profile.b entitlementMapper, AbstractC5040y ioDispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(entitlementMapper, "entitlementMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = service;
        this.c = entitlementMapper;
        this.d = ioDispatcher;
    }

    public e(androidx.work.impl.model.c userProperties, com.quizlet.analytics.marketing.appsflyer.e appsFlyer) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(appsFlyer, "appsFlyer");
        this.b = userProperties;
        this.c = appsFlyer;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.d = dVar;
    }

    public e(com.quizlet.data.repository.explanations.myexplanations.a factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
    }

    public e(Context applicationContext, ObjectWriter objectWriter, AbstractC5040y ioDispatcher) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        Intrinsics.checkNotNullParameter(objectWriter, "objectWriter");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = applicationContext;
        this.c = objectWriter;
        this.d = ioDispatcher;
    }

    public e(w roundOutline) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(roundOutline, "roundOutline");
        this.b = roundOutline;
        this.c = kotlin.collections.K.a;
        this.d = CollectionsKt.y0(CollectionsKt.C0(roundOutline.a, roundOutline.b));
    }

    public e(com.quizlet.braze.e brazeUserManager, PushNotificationLogger pushNotificationLogger) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(brazeUserManager, "brazeUserManager");
        Intrinsics.checkNotNullParameter(pushNotificationLogger, "pushNotificationLogger");
        this.b = brazeUserManager;
        this.c = pushNotificationLogger;
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 3:
                break;
            case 7:
                this.b = new HashMap();
                this.c = new HashMap();
                this.d = C3443e.c;
                break;
            default:
                this.b = new AtomicReference(androidx.compose.runtime.internal.e.b);
                this.c = new Object();
                break;
        }
    }

    public e(com.google.firebase.h hVar, com.google.firebase.installations.d dVar, com.google.firebase.remoteconfig.internal.e eVar, com.google.firebase.remoteconfig.internal.b bVar, Context context, String str, j jVar, ScheduledExecutorService scheduledExecutorService) {
        this.a = 9;
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        this.b = linkedHashSet;
        this.c = new com.google.firebase.remoteconfig.internal.h(hVar, dVar, eVar, bVar, context, str, linkedHashSet, jVar, scheduledExecutorService);
        this.d = scheduledExecutorService;
    }

    public e(Context context, TypedArray typedArray) {
        this.a = 1;
        this.b = context;
        this.c = typedArray;
    }
}

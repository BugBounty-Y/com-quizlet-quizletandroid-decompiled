package com.quizlet.data.interactor.progress;

import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Looper;
import androidx.camera.core.impl.utils.executor.f;
import androidx.compose.animation.core.AbstractC0267t;
import androidx.compose.animation.core.E;
import androidx.compose.animation.core.InterfaceC0269u;
import androidx.compose.animation.core.Q0;
import androidx.compose.runtime.internal.j;
import com.bumptech.glide.load.engine.p;
import com.bumptech.glide.load.engine.q;
import com.bumptech.glide.load.engine.v;
import com.google.android.gms.auth.api.signin.internal.h;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.Ah;
import com.google.android.gms.internal.ads.C1847ao;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.Lr;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.measurement.internal.Y;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;
import com.quizlet.infra.legacysyncengine.net.request.g;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.o0;
import java.lang.ref.ReferenceQueue;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.i;
import kotlin.ranges.l;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c implements Q0, Pv {
    public static long e;
    public final Object a;
    public Object b;
    public Object c;
    public Object d;

    public c(C2584rr c2584rr, Pq pq, Tq tq, Ah ah) {
        this.a = pq;
        this.b = tq;
        this.c = ah;
        this.d = c2584rr;
    }

    @Override // androidx.compose.animation.core.N0
    public long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        i iVarA = l.h(0, abstractC0267t.b()).iterator();
        long jMax = 0;
        while (iVarA.c) {
            int iNextInt = iVarA.nextInt();
            jMax = Math.max(jMax, ((InterfaceC0269u) this.a).get(iNextInt).c(abstractC0267t.a(iNextInt), abstractC0267t2.a(iNextInt), abstractC0267t3.a(iNextInt)));
        }
        return jMax;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0093  */
    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo15c(java.lang.Object r15) {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.progress.c.mo15c(java.lang.Object):void");
    }

    public synchronized void d(p pVar, q qVar) {
        com.bumptech.glide.load.engine.a aVar = (com.bumptech.glide.load.engine.a) ((HashMap) this.b).put(pVar, new com.bumptech.glide.load.engine.a(pVar, qVar, (ReferenceQueue) this.c));
        if (aVar != null) {
            aVar.c = null;
            aVar.clear();
        }
    }

    public void e(com.bumptech.glide.load.engine.a aVar) {
        v vVar;
        synchronized (this) {
            ((HashMap) this.b).remove(aVar.a);
            if (aVar.b && (vVar = aVar.c) != null) {
                ((com.bumptech.glide.load.engine.l) this.d).d(aVar.a, new q(vVar, true, false, aVar.a, (com.bumptech.glide.load.engine.l) this.d));
            }
        }
    }

    public J f(long j, long j2, io.reactivex.rxjava3.core.p stopToken) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        o0 o0VarB = ((androidx.work.impl.model.c) this.c).b(stopToken, new a(this, j, j2, 0));
        b bVar = b.a;
        g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar2 = io.reactivex.rxjava3.internal.functions.d.c;
        J j3 = new J(new B(o0VarB, bVar, gVar, bVar2, bVar2), new com.lyft.android.scissors.b(this, 7), 5);
        Intrinsics.checkNotNullExpressionValue(j3, "onErrorReturn(...)");
        return j3;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.login.common.interactors.u
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.login.common.interactors.u r0 = (com.quizlet.login.common.interactors.u) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.u r0 = new com.quizlet.login.common.interactors.u
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L39
            if (r2 == r5) goto L33
            if (r2 != r4) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            com.quizlet.data.interactor.progress.c r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.login.common.interactors.v r8 = new com.quizlet.login.common.interactors.v
            r8.<init>(r7, r6, r3)
            r0.j = r6
            r0.m = r5
            java.lang.Object r7 = r6.d
            kotlinx.coroutines.y r7 = (kotlinx.coroutines.AbstractC5040y) r7
            java.lang.Object r8 = kotlinx.coroutines.E.J(r7, r8, r0)
            if (r8 != r1) goto L50
            goto L68
        L50:
            r7 = r6
        L51:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            com.quizlet.login.authentication.data.i r8 = (com.quizlet.login.authentication.data.i) r8
            java.lang.Object r7 = r7.c
            androidx.compose.runtime.internal.j r7 = (androidx.compose.runtime.internal.j) r7
            r0.j = r3
            r0.m = r4
            java.lang.String r2 = "google"
            java.lang.Object r7 = r7.s(r8, r2, r3, r0)
            if (r7 != r1) goto L69
        L68:
            return r1
        L69:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.progress.c.g(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x011b A[Catch: NumberFormatException | JSONException -> 0x0123, NumberFormatException | JSONException -> 0x0123, TRY_LEAVE, TryCatch #0 {NumberFormatException | JSONException -> 0x0123, blocks: (B:10:0x0031, B:44:0x009d, B:44:0x009d, B:45:0x00ab, B:45:0x00ab, B:47:0x00b8, B:47:0x00b8, B:49:0x00ca, B:49:0x00ca, B:50:0x00d3, B:50:0x00d3, B:51:0x00d7, B:51:0x00d7, B:53:0x00e4, B:53:0x00e4, B:55:0x00f6, B:55:0x00f6, B:56:0x00ff, B:56:0x00ff, B:57:0x0103, B:57:0x0103, B:58:0x010f, B:58:0x010f, B:59:0x011b, B:59:0x011b), top: B:71:0x0031, outer: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.os.Bundle h() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 347
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.progress.c.h():android.os.Bundle");
    }

    public void i(Bundle bundle) throws JSONException {
        Iterator<String> it2;
        JSONObject jSONObject;
        boolean zF0;
        I i;
        Bundle bundle2 = bundle == null ? new Bundle() : new Bundle(bundle);
        O o = (O) this.d;
        SharedPreferences sharedPreferencesX = o.X();
        Y y = (Y) o.b;
        SharedPreferences.Editor editorEdit = sharedPreferencesX.edit();
        int size = bundle2.size();
        String str = (String) this.a;
        if (size == 0) {
            editorEdit.remove(str);
        } else {
            JSONArray jSONArray = new JSONArray();
            Iterator<String> it3 = bundle2.keySet().iterator();
            while (it3.hasNext()) {
                String next = it3.next();
                Object obj = bundle2.get(next);
                if (obj != null) {
                    try {
                        jSONObject = new JSONObject();
                        jSONObject.put("n", next);
                        E3.b();
                        zF0 = y.g.f0(null, AbstractC3893t.W0);
                        i = y.i;
                    } catch (JSONException e2) {
                        e = e2;
                        it2 = it3;
                    }
                    if (zF0) {
                        it2 = it3;
                        try {
                        } catch (JSONException e3) {
                            e = e3;
                            I i2 = y.i;
                            Y.k(i2);
                            i2.g.g("Cannot serialize bundle value to SharedPreferences", e);
                            it3 = it2;
                        }
                        if (obj instanceof String) {
                            jSONObject.put("v", obj.toString());
                            jSONObject.put("t", "s");
                        } else if (obj instanceof Long) {
                            jSONObject.put("v", obj.toString());
                            jSONObject.put("t", "l");
                        } else if (obj instanceof int[]) {
                            jSONObject.put("v", Arrays.toString((int[]) obj));
                            jSONObject.put("t", "ia");
                        } else if (obj instanceof long[]) {
                            jSONObject.put("v", Arrays.toString((long[]) obj));
                            jSONObject.put("t", "la");
                        } else if (obj instanceof Double) {
                            jSONObject.put("v", obj.toString());
                            jSONObject.put("t", "d");
                        } else {
                            Y.k(i);
                            i.g.g("Cannot serialize bundle value to SharedPreferences. Type", obj.getClass());
                            it3 = it2;
                        }
                        jSONArray.put(jSONObject);
                        it3 = it2;
                    } else {
                        it2 = it3;
                        jSONObject.put("v", obj.toString());
                        if (obj instanceof String) {
                            jSONObject.put("t", "s");
                        } else if (obj instanceof Long) {
                            jSONObject.put("t", "l");
                        } else if (obj instanceof Double) {
                            jSONObject.put("t", "d");
                        } else {
                            Y.k(i);
                            i.g.g("Cannot serialize bundle value to SharedPreferences. Type", obj.getClass());
                            it3 = it2;
                        }
                        jSONArray.put(jSONObject);
                        it3 = it2;
                    }
                }
            }
            editorEdit.putString(str, jSONArray.toString());
        }
        editorEdit.apply();
        this.c = bundle2;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        if (((AbstractC0267t) this.c) == null) {
            this.c = abstractC0267t3.c();
        }
        AbstractC0267t abstractC0267t4 = (AbstractC0267t) this.c;
        if (abstractC0267t4 == null) {
            Intrinsics.m("velocityVector");
            throw null;
        }
        int iB = abstractC0267t4.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t5 = (AbstractC0267t) this.c;
            if (abstractC0267t5 == null) {
                Intrinsics.m("velocityVector");
                throw null;
            }
            abstractC0267t5.e(((InterfaceC0269u) this.a).get(i).b(j, abstractC0267t.a(i), abstractC0267t2.a(i), abstractC0267t3.a(i)), i);
        }
        AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.c;
        if (abstractC0267t6 != null) {
            return abstractC0267t6;
        }
        Intrinsics.m("velocityVector");
        throw null;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t n(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        if (((AbstractC0267t) this.d) == null) {
            this.d = abstractC0267t3.c();
        }
        AbstractC0267t abstractC0267t4 = (AbstractC0267t) this.d;
        if (abstractC0267t4 == null) {
            Intrinsics.m("endVelocityVector");
            throw null;
        }
        int iB = abstractC0267t4.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t5 = (AbstractC0267t) this.d;
            if (abstractC0267t5 == null) {
                Intrinsics.m("endVelocityVector");
                throw null;
            }
            abstractC0267t5.e(((InterfaceC0269u) this.a).get(i).d(abstractC0267t.a(i), abstractC0267t2.a(i), abstractC0267t3.a(i)), i);
        }
        AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.d;
        if (abstractC0267t6 != null) {
            return abstractC0267t6;
        }
        Intrinsics.m("endVelocityVector");
        throw null;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        if (((AbstractC0267t) this.b) == null) {
            this.b = abstractC0267t.c();
        }
        AbstractC0267t abstractC0267t4 = (AbstractC0267t) this.b;
        if (abstractC0267t4 == null) {
            Intrinsics.m("valueVector");
            throw null;
        }
        int iB = abstractC0267t4.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t5 = (AbstractC0267t) this.b;
            if (abstractC0267t5 == null) {
                Intrinsics.m("valueVector");
                throw null;
            }
            abstractC0267t5.e(((InterfaceC0269u) this.a).get(i).e(j, abstractC0267t.a(i), abstractC0267t2.a(i), abstractC0267t3.a(i)), i);
        }
        AbstractC0267t abstractC0267t6 = (AbstractC0267t) this.b;
        if (abstractC0267t6 != null) {
            return abstractC0267t6;
        }
        Intrinsics.m("valueVector");
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Pq pq = (Pq) this.a;
        if (pq == null) {
            return;
        }
        pq.h(false);
        Tq tq = (Tq) this.b;
        if (tq == null) {
            ((C2584rr) this.d).f.b(pq.l());
        } else {
            tq.a(pq);
            tq.h();
        }
    }

    public c(Looper looper, Looper looper2, C1847ao c1847ao, Lr lr) {
        this.a = c1847ao.a(looper, null);
        this.b = c1847ao.a(looper2, null);
        this.c = 0;
        this.d = lr;
    }

    public c(O o, String str) {
        this.d = o;
        u.e(str);
        this.a = str;
        this.b = new Bundle();
    }

    public c(com.quizlet.login.common.interactors.d dataSource, com.quizlet.quizletandroid.ui.folder.logging.a classFolderMapper, com.quizlet.quizletandroid.ui.folder.logging.a folderMapper, com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(classFolderMapper, "classFolderMapper");
        Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        this.a = dataSource;
        this.b = classFolderMapper;
        this.c = folderMapper;
        this.d = userMapper;
    }

    public c(io.ktor.client.plugins.api.d apiClient, com.quizlet.qutils.string.c state, j handleLoginResponseUseCase, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = apiClient;
        this.b = state;
        this.c = handleLoginResponseUseCase;
        this.d = ioDispatcher;
    }

    public c(com.quizlet.data.repository.progress.b defaultRepository, com.quizlet.data.repository.folderwithcreator.e cacheRepository, androidx.work.impl.model.c dispatcher, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(defaultRepository, "defaultRepository");
        Intrinsics.checkNotNullParameter(cacheRepository, "cacheRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = defaultRepository;
        this.b = cacheRepository;
        this.c = dispatcher;
        this.d = logger;
    }

    public c(SQLiteDatabase sQLiteDatabase, OrmLiteSqliteOpenHelper ormLiteSqliteOpenHelper, ConnectionSource connectionSource, com.google.firebase.messaging.p pVar) {
        this.a = sQLiteDatabase;
        this.b = ormLiteSqliteOpenHelper;
        this.c = connectionSource;
        this.d = pVar;
    }

    public c() {
        ExecutorService executorServiceNewSingleThreadExecutor = Executors.newSingleThreadExecutor(new f(2));
        this.b = new HashMap();
        this.c = new ReferenceQueue();
        this.a = executorServiceNewSingleThreadExecutor;
        executorServiceNewSingleThreadExecutor.execute(new androidx.appcompat.app.J(this, 16));
    }

    public c(InterfaceC0269u interfaceC0269u) {
        this.a = interfaceC0269u;
    }

    public c(E e2) {
        this(new h(e2, 8));
    }
}

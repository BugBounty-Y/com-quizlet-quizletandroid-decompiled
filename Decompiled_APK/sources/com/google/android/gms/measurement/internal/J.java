package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import com.google.firebase.perf.util.Timer;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields;
import java.io.IOException;
import java.lang.ref.Reference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import okhttp3.C5072a;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;

/* loaded from: classes2.dex */
public final class J implements InterfaceC5077f {
    public final /* synthetic */ int a = 7;
    public long b;
    public Object c;
    public Object d;
    public Object e;

    public /* synthetic */ J(C3860c c3860c) {
        this.e = c3860c;
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0062, code lost:
    
        if (r8 == r1) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.google.android.gms.measurement.internal.J r5, long r6, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5.getClass()
            boolean r0 = r8 instanceof com.quizlet.features.onboarding.ell.t
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.features.onboarding.ell.t r0 = (com.quizlet.features.onboarding.ell.t) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.onboarding.ell.t r0 = new com.quizlet.features.onboarding.ell.t
            r0.<init>(r5, r8)
        L1b:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3d
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L65
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            long r6 = r0.k
            com.google.android.gms.measurement.internal.J r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4d
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r8 = r5.g(r6, r0)
            if (r8 != r1) goto L4d
            goto L64
        L4d:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto L6e
            java.lang.Object r5 = r5.e
            com.lyft.android.scissors.b r5 = (com.lyft.android.scissors.b) r5
            r8 = 0
            r0.j = r8
            r0.n = r3
            java.lang.Object r8 = r5.k(r6, r0)
            if (r8 != r1) goto L65
        L64:
            return r1
        L65:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r5 = r8.booleanValue()
            if (r5 != 0) goto L6e
            goto L6f
        L6e:
            r4 = 0
        L6f:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.J.a(com.google.android.gms.measurement.internal.J, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final ArrayList b(J j, Map map, List list) {
        Object next;
        j.getClass();
        ArrayList arrayList = new ArrayList(map.size());
        for (Map.Entry entry : map.entrySet()) {
            long jLongValue = ((Number) entry.getKey()).longValue();
            Iterator it2 = list.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    next = null;
                    break;
                }
                next = it2.next();
                if (((DBGroup) next).getId() == ((Number) entry.getKey()).longValue()) {
                    break;
                }
            }
            DBGroup dBGroup = (DBGroup) next;
            String title = dBGroup != null ? dBGroup.getTitle() : null;
            if (title == null) {
                title = "";
            }
            arrayList.add(new com.quizlet.data.model.C(((List) entry.getValue()).size(), jLongValue, title));
        }
        return arrayList;
    }

    public static J k(zzbh zzbhVar) {
        Bundle bundleA = zzbhVar.b.a();
        long j = zzbhVar.d;
        return new J(zzbhVar.a, zzbhVar.c, bundleA, j);
    }

    public boolean c(C5072a address, okhttp3.internal.connection.g call, ArrayList arrayList, boolean z) {
        Intrinsics.checkNotNullParameter(address, "address");
        Intrinsics.checkNotNullParameter(call, "call");
        Iterator it2 = ((ConcurrentLinkedQueue) this.e).iterator();
        while (true) {
            if (!it2.hasNext()) {
                return false;
            }
            okhttp3.internal.connection.i connection = (okhttp3.internal.connection.i) it2.next();
            Intrinsics.checkNotNullExpressionValue(connection, "connection");
            synchronized (connection) {
                if (z) {
                    if (connection.g != null) {
                    }
                    Unit unit = Unit.a;
                }
                if (connection.h(address, arrayList)) {
                    call.c(connection);
                    return true;
                }
                Unit unit2 = Unit.a;
            }
        }
    }

    public io.reactivex.rxjava3.core.i d(Set setIds) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) this.d;
        com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) this.c;
        if (aVar == null) {
            aVar = new com.quizlet.features.infra.studysetting.datasource.a(loader, setIds);
            this.d = aVar;
        }
        io.reactivex.rxjava3.core.i source1 = aVar.f();
        Intrinsics.checkNotNullExpressionValue(source1, "getObservable(...)");
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) this.e;
        if (aVar2 == null) {
            Intrinsics.checkNotNullParameter(loader, "loader");
            Intrinsics.checkNotNullParameter(setIds, "setIds");
            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.SELECTED_TERM);
            bVar.c(DBSelectedTermFields.SET, setIds, null);
            bVar.b(Long.valueOf(this.b), DBSelectedTermFields.PERSON);
            aVar2 = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar.a());
            this.e = aVar2;
        }
        io.reactivex.rxjava3.core.i source2 = aVar2.f();
        Intrinsics.checkNotNullExpressionValue(source2, "getObservable(...)");
        Intrinsics.checkNotNullParameter(source1, "source1");
        Intrinsics.checkNotNullParameter(source2, "source2");
        io.reactivex.rxjava3.core.i iVarD = io.reactivex.rxjava3.core.i.d(source1, source2, io.reactivex.rxjava3.kotlin.a.b);
        Intrinsics.checkNotNullExpressionValue(iVarD, "Observable.combineLatest…> { t1, t2 -> t1 to t2 })");
        return iVarD;
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00be, code lost:
    
        if (r14 == r0) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum e(long r12, kotlin.coroutines.jvm.internal.c r14) {
        /*
            Method dump skipped, instructions count: 196
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.J.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r14, java.lang.String r15, long r16, long r18, kotlin.coroutines.jvm.internal.c r20) {
        /*
            r13 = this;
            r0 = r20
            boolean r1 = r0 instanceof com.quizlet.data.interactor.folder.g
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.data.interactor.folder.g r1 = (com.quizlet.data.interactor.folder.g) r1
            int r2 = r1.l
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.l = r2
        L14:
            r9 = r1
            goto L1c
        L16:
            com.quizlet.data.interactor.folder.g r1 = new com.quizlet.data.interactor.folder.g
            r1.<init>(r13, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r9.j
            kotlin.coroutines.intrinsics.a r10 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.l
            r11 = 1
            if (r1 == 0) goto L35
            if (r1 != r11) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r0)     // Catch: java.lang.Throwable -> L2b
            goto L5b
        L2b:
            r0 = move-exception
            goto L60
        L2d:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.model.F0 r7 = new com.quizlet.data.model.F0
            long r0 = r13.b
            r7.<init>(r0, r14, r15)
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Throwable -> L2b
            java.lang.Object r0 = r13.e     // Catch: java.lang.Throwable -> L2b
            r12 = r0
            kotlinx.coroutines.y r12 = (kotlinx.coroutines.AbstractC5040y) r12     // Catch: java.lang.Throwable -> L2b
            com.quizlet.data.interactor.folder.h r0 = new com.quizlet.data.interactor.folder.h     // Catch: java.lang.Throwable -> L2b
            r8 = 0
            r5 = r13
            r6 = r14
            r1 = r16
            r3 = r18
            r0.<init>(r1, r3, r5, r6, r7, r8)     // Catch: java.lang.Throwable -> L2b
            r9.l = r11     // Catch: java.lang.Throwable -> L2b
            java.lang.Object r0 = kotlinx.coroutines.E.J(r12, r0, r9)     // Catch: java.lang.Throwable -> L2b
            if (r0 != r10) goto L5b
            return r10
        L5b:
            com.quizlet.data.model.d0 r0 = (com.quizlet.data.model.AbstractC4119d0) r0     // Catch: java.lang.Throwable -> L2b
            kotlin.p r1 = kotlin.r.b     // Catch: java.lang.Throwable -> L2b
            return r0
        L60:
            kotlin.p r1 = kotlin.r.b
            kotlin.q r0 = androidx.glance.appwidget.protobuf.Z.b(r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.J.f(java.lang.String, java.lang.String, long, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.onboarding.ell.r
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.onboarding.ell.r r0 = (com.quizlet.features.onboarding.ell.r) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.onboarding.ell.r r0 = new com.quizlet.features.onboarding.ell.r
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3f
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            java.lang.Object r7 = r4.e
            com.lyft.android.scissors.b r7 = (com.lyft.android.scissors.b) r7
            java.lang.Object r7 = r7.i(r5, r0)
            if (r7 != r1) goto L3f
            return r1
        L3f:
            java.lang.Integer r7 = (java.lang.Integer) r7
            r5 = 0
            if (r7 == 0) goto L4e
            int r6 = r7.intValue()
            r7 = 2
            if (r6 > r7) goto L4c
            goto L4d
        L4c:
            r3 = r5
        L4d:
            r5 = r3
        L4e:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.J.g(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public int h(okhttp3.internal.connection.i iVar, long j) {
        byte[] bArr = okhttp3.internal.b.a;
        ArrayList arrayList = iVar.p;
        int i = 0;
        while (i < arrayList.size()) {
            Reference reference = (Reference) arrayList.get(i);
            if (reference.get() != null) {
                i++;
            } else {
                String str = "A connection to " + iVar.b.a.h + " was leaked. Did you forget to close a response body?";
                okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
                okhttp3.internal.platform.o.a.j(((okhttp3.internal.connection.e) reference).a, str);
                arrayList.remove(i);
                iVar.j = true;
                if (arrayList.isEmpty()) {
                    iVar.q = j - this.b;
                    return 0;
                }
            }
        }
        return arrayList.size();
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x010e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.measurement.U0 i(com.google.android.gms.internal.measurement.U0 r19, java.lang.String r20) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 578
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.J.i(com.google.android.gms.internal.measurement.U0, java.lang.String):com.google.android.gms.internal.measurement.U0");
    }

    public zzbh j() {
        zzbf zzbfVar = new zzbf(new Bundle((Bundle) this.e));
        return new zzbh((String) this.c, zzbfVar, (String) this.d, this.b);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e interfaceC5076e, IOException iOException) {
        okhttp3.C c = ((okhttp3.internal.connection.g) interfaceC5076e).b;
        com.google.firebase.perf.metrics.d dVar = (com.google.firebase.perf.metrics.d) this.d;
        if (c != null) {
            okhttp3.s sVar = c.a;
            if (sVar != null) {
                dVar.l(sVar.k().toString());
            }
            String str = c.b;
            if (str != null) {
                dVar.c(str);
            }
        }
        dVar.g(this.b);
        Z.m((Timer) this.e, dVar, dVar);
        ((InterfaceC5077f) this.c).onFailure(interfaceC5076e, iOException);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e interfaceC5076e, okhttp3.H h) {
        FirebasePerfOkHttpClient.a(h, (com.google.firebase.perf.metrics.d) this.d, this.b, ((Timer) this.e).a());
        ((InterfaceC5077f) this.c).onResponse(interfaceC5076e, h);
    }

    public String toString() {
        switch (this.a) {
            case 0:
                String string = ((Bundle) this.e).toString();
                StringBuilder sb = new StringBuilder("origin=");
                sb.append((String) this.d);
                sb.append(",name=");
                return AbstractC0147y.g(sb, (String) this.c, ",params=", string);
            default:
                return super.toString();
        }
    }

    public J(String str, String str2, Bundle bundle, long j) {
        this.c = str;
        this.d = str2;
        this.e = bundle;
        this.b = j;
    }

    public J(com.quizlet.data.interactor.school.b showUpsellFeature, com.quizlet.features.setpage.upsell.a preferenceManager, com.onetrust.otpublishers.headless.UI.fragment.q logger, long j) {
        Intrinsics.checkNotNullParameter(showUpsellFeature, "showUpsellFeature");
        Intrinsics.checkNotNullParameter(preferenceManager, "preferenceManager");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.c = showUpsellFeature;
        this.d = preferenceManager;
        this.e = logger;
        this.b = j;
    }

    public J(String directory, long j, kotlinx.coroutines.scheduling.e dispatcher) {
        Intrinsics.checkNotNullParameter(directory, "directory");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.c = directory;
        this.b = j;
        this.d = dispatcher;
    }

    public J(AbstractC5040y dispatcher, com.quizlet.remote.model.notes.e onboardingELLType, com.lyft.android.scissors.b preferences, long j) {
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(onboardingELLType, "onboardingELLType");
        Intrinsics.checkNotNullParameter(preferences, "preferences");
        this.c = dispatcher;
        this.d = onboardingELLType;
        this.e = preferences;
        this.b = j;
    }

    public J(com.quizlet.featuregate.features.studymodes.learn.a tasksExperiment, androidx.work.impl.model.c userProperties, com.quizlet.data.interactor.metering.b getMeteringInfoUseCase, long j) {
        Intrinsics.checkNotNullParameter(tasksExperiment, "tasksExperiment");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(getMeteringInfoUseCase, "getMeteringInfoUseCase");
        this.c = tasksExperiment;
        this.d = userProperties;
        this.e = getMeteringInfoUseCase;
        this.b = j;
    }

    public J(long j, com.quizlet.infra.legacysyncengine.net.c loader) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.c = loader;
        this.b = j;
    }

    public J(com.quizlet.data.repository.folder.i folderRepository, androidx.work.impl.model.n courseRepository, long j, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        Intrinsics.checkNotNullParameter(courseRepository, "courseRepository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.c = folderRepository;
        this.d = courseRepository;
        this.b = j;
        this.e = ioDispatcher;
    }

    public J(long j, com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.data.repository.studysetwithcreatorinclass.g repository, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = j;
        this.c = loader;
        this.d = repository;
        this.e = ioDispatcher;
    }

    public J(com.quizlet.infra.legacysyncengine.net.c loader, long j, io.ktor.client.plugins.api.d getStudySetsWithCreatorAndClassificationUseCase, com.quizlet.shared.usecase.srs.a localStudySetMapper) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(getStudySetsWithCreatorAndClassificationUseCase, "getStudySetsWithCreatorAndClassificationUseCase");
        Intrinsics.checkNotNullParameter(localStudySetMapper, "localStudySetMapper");
        this.c = loader;
        this.b = j;
        this.d = getStudySetsWithCreatorAndClassificationUseCase;
        this.e = localStudySetMapper;
    }

    public J(okhttp3.internal.concurrent.d taskRunner) {
        TimeUnit timeUnit = TimeUnit.MINUTES;
        Intrinsics.checkNotNullParameter(taskRunner, "taskRunner");
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        this.b = timeUnit.toNanos(5L);
        this.c = taskRunner.e();
        this.d = new okhttp3.internal.concurrent.b(this, android.support.v4.media.session.a.t(new StringBuilder(), okhttp3.internal.b.g, " ConnectionPool"));
        this.e = new ConcurrentLinkedQueue();
    }

    public J(InterfaceC5077f interfaceC5077f, com.google.firebase.perf.transport.f fVar, Timer timer, long j) {
        this.c = interfaceC5077f;
        this.d = new com.google.firebase.perf.metrics.d(fVar);
        this.b = j;
        this.e = timer;
    }
}

package com.quizlet.data.interactor.school;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.camera.camera2.internal.C0138o;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import androidx.work.impl.model.v;
import com.bumptech.glide.load.engine.j;
import com.bumptech.glide.load.engine.z;
import com.bumptech.glide.load.model.q;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.internal.k;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.firebase.crashlytics.internal.common.m;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.match.data.a0;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.learnpaywall.LearnPaywallFragment;
import java.io.File;
import java.text.BreakIterator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements androidx.compose.ui.text.android.selection.e, com.bumptech.glide.load.data.d, com.google.android.gms.tasks.a, com.google.android.gms.tasks.e, io.reactivex.rxjava3.functions.h, dagger.android.b, io.reactivex.rxjava3.functions.b {
    public static b d;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public static v p(Context context, String str) {
        try {
            return new v(11, context.getPackageManager().getResourcesForApplication(str), str);
        } catch (PackageManager.NameNotFoundException unused) {
            Log.w("OssLicenses", "Unable to get resources for " + str + ", using local resources.");
            return new v(11, context.getResources(), context.getPackageName());
        }
    }

    public static b q(AbstractActivityC0055k abstractActivityC0055k) {
        if (d == null) {
            b bVar = new b(abstractActivityC0055k);
            d = bVar;
            bVar.b = new com.google.android.gms.oss.licenses.c((Context) bVar.c, null, com.google.android.gms.oss.licenses.c.l, null, com.google.android.gms.common.api.d.c);
        }
        return d;
    }

    @Override // com.bumptech.glide.load.data.d
    public void a(Exception exc) {
        z zVar = (z) this.c;
        q qVar = (q) this.b;
        q qVar2 = zVar.f;
        if (qVar2 == null || qVar2 != qVar) {
            return;
        }
        z zVar2 = (z) this.c;
        q qVar3 = (q) this.b;
        com.bumptech.glide.load.engine.h hVar = zVar2.b;
        com.bumptech.glide.load.engine.d dVar = zVar2.g;
        com.bumptech.glide.load.data.e eVar = qVar3.c;
        hVar.c(dVar, exc, eVar, eVar.g());
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Boolean isUnderage = (Boolean) obj;
        Long l = (Long) obj2;
        Intrinsics.checkNotNullParameter(isUnderage, "isUnderage");
        com.quizlet.features.match.highscore.a aVar = (com.quizlet.features.match.highscore.a) this.b;
        if (l != null) {
            long jLongValue = l.longValue();
            long j = aVar.b;
            if (j == jLongValue && !isUnderage.booleanValue()) {
                double d2 = j / 10.0d;
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar2 = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.c;
                com.quizlet.infra.legacysyncengine.managers.d dVar = aVar2.c;
                DBUser dBUser = dVar.r;
                UserInfoCache userInfoCache = dVar.e;
                String imageUrl = dBUser != null ? dBUser.getImageUrl() : userInfoCache.getProfileImage();
                DBUser dBUser2 = dVar.r;
                aVar2.n.j(new a0(d2, imageUrl, dBUser2 != null ? dBUser2.getUsername() : userInfoCache.getUsername()));
                aVar2.g.c.I("match_high_score_challenge_modal");
                assistantMode.refactored.a.p(aVar2.e.b, "PREF_NEW_PROMPT_HAS_BEEN_SHOWN", true);
            }
        }
        return Unit.a;
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int b(int i) {
        CharSequence charSequence;
        do {
            androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.c;
            fVar.b(i);
            i = ((BreakIterator) fVar.e).following(i);
            if (i != -1) {
                charSequence = (CharSequence) this.b;
                if (i == charSequence.length()) {
                }
            }
            return -1;
        } while (Character.isWhitespace(charSequence.charAt(i)));
        return i;
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int c(int i) {
        do {
            androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.c;
            fVar.b(i);
            i = ((BreakIterator) fVar.e).preceding(i);
            if (i == -1 || i == 0) {
                return -1;
            }
        } while (Character.isWhitespace(((CharSequence) this.b).charAt(i - 1)));
        return i;
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        LearnPaywallFragment learnPaywallFragment = (LearnPaywallFragment) obj;
        C4622e c4622e = (C4622e) this.c;
        learnPaywallFragment.a = c4622e.a();
        learnPaywallFragment.b = ((u) this.b).S0();
        learnPaywallFragment.f = c4622e.e();
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int e(int i) {
        do {
            androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.c;
            fVar.b(i);
            i = ((BreakIterator) fVar.e).preceding(i);
            if (i == -1) {
                return -1;
            }
        } while (Character.isWhitespace(((CharSequence) this.b).charAt(i)));
        return i;
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int f(int i) {
        do {
            androidx.compose.ui.text.android.selection.f fVar = (androidx.compose.ui.text.android.selection.f) this.c;
            fVar.b(i);
            i = ((BreakIterator) fVar.e).following(i);
            if (i == -1) {
                return -1;
            }
        } while (Character.isWhitespace(((CharSequence) this.b).charAt(i - 1)));
        return i;
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        Boolean bool = (Boolean) obj;
        boolean zBooleanValue = bool.booleanValue();
        m mVar = (m) this.c;
        if (zBooleanValue) {
            Log.isLoggable("FirebaseCrashlytics", 3);
            boolean zBooleanValue2 = bool.booleanValue();
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = mVar.b;
            if (!zBooleanValue2) {
                gVar.getClass();
                throw new IllegalStateException("An invalid data collection token was used.");
            }
            ((com.google.android.gms.tasks.f) gVar.f).d(null);
            return ((com.google.android.gms.tasks.m) this.b).n(mVar.e.a, new com.google.android.material.floatingactionbutton.c(this, 1));
        }
        Log.isLoggable("FirebaseCrashlytics", 2);
        Iterator it2 = com.google.firebase.crashlytics.internal.persistence.c.e(mVar.g.c.listFiles(m.r)).iterator();
        while (it2.hasNext()) {
            ((File) it2.next()).delete();
        }
        com.google.firebase.crashlytics.internal.persistence.c cVar = ((com.google.firebase.crashlytics.internal.persistence.a) mVar.m.b).b;
        com.google.firebase.crashlytics.internal.persistence.a.a(com.google.firebase.crashlytics.internal.persistence.c.e(cVar.e.listFiles()));
        com.google.firebase.crashlytics.internal.persistence.a.a(com.google.firebase.crashlytics.internal.persistence.c.e(cVar.f.listFiles()));
        com.google.firebase.crashlytics.internal.persistence.a.a(com.google.firebase.crashlytics.internal.persistence.c.e(cVar.g.listFiles()));
        mVar.q.d(null);
        return S3.i(null);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        Bundle bundle;
        com.google.android.gms.cloudmessaging.a aVar = (com.google.android.gms.cloudmessaging.a) this.b;
        aVar.getClass();
        return (task.l() && (bundle = (Bundle) task.h()) != null && bundle.containsKey("google.messenger")) ? aVar.a((Bundle) this.c).n(com.google.android.gms.cloudmessaging.f.c, com.google.android.gms.cloudmessaging.c.d) : task;
    }

    @Override // com.bumptech.glide.load.data.d
    public void i(Object obj) {
        z zVar = (z) this.c;
        q qVar = (q) this.b;
        q qVar2 = zVar.f;
        if (qVar2 == null || qVar2 != qVar) {
            return;
        }
        z zVar2 = (z) this.c;
        q qVar3 = (q) this.b;
        j jVar = zVar2.a.p;
        if (obj != null && jVar.a(qVar3.c.g())) {
            zVar2.e = obj;
            zVar2.b.k(2);
        } else {
            com.bumptech.glide.load.engine.h hVar = zVar2.b;
            com.bumptech.glide.load.e eVar = qVar3.a;
            com.bumptech.glide.load.data.e eVar2 = qVar3.c;
            hVar.a(eVar, obj, eVar2, eVar2.g(), zVar2.g);
        }
    }

    public void j() {
        com.quizlet.data.repository.course.membership.c cVar = (com.quizlet.data.repository.course.membership.c) this.b;
        if (cVar != null) {
            ((AtomicBoolean) cVar.b).set(true);
            ((ScheduledFuture) cVar.a).cancel(true);
        }
        this.b = null;
    }

    public LinkedHashSet k() {
        LinkedHashSet linkedHashSet;
        synchronized (this.b) {
            linkedHashSet = new LinkedHashSet(((LinkedHashMap) this.c).values());
        }
        return linkedHashSet;
    }

    public void l(C0138o c0138o) {
        synchronized (this.b) {
            try {
                c0138o.getClass();
                for (String str : new LinkedHashSet((ArrayList) c0138o.g)) {
                    AbstractC3053s1.f(3, "CameraRepository");
                    ((LinkedHashMap) this.c).put(str, c0138o.a(str));
                }
            } catch (CameraUnavailableException e) {
                throw new InitializationException(e);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(long r11, com.quizlet.generated.enums.U1 r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.school.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.school.a r0 = (com.quizlet.data.interactor.school.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.school.a r0 = new com.quizlet.data.interactor.school.a
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.interactor.school.b r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)     // Catch: java.lang.Exception -> L59
            goto L55
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r10.b     // Catch: java.lang.Exception -> L58
            r8 = r14
            com.quizlet.data.repository.set.f r8 = (com.quizlet.data.repository.set.f) r8     // Catch: java.lang.Exception -> L58
            r0.j = r10     // Catch: java.lang.Exception -> L58
            r0.m = r3     // Catch: java.lang.Exception -> L58
            com.quizlet.remote.model.school.b r4 = new com.quizlet.remote.model.school.b     // Catch: java.lang.Exception -> L58
            r9 = 0
            r5 = r11
            r7 = r13
            r4.<init>(r5, r7, r8, r9)     // Catch: java.lang.Exception -> L58
            java.lang.Object r11 = r8.d     // Catch: java.lang.Exception -> L58
            kotlinx.coroutines.y r11 = (kotlinx.coroutines.AbstractC5040y) r11     // Catch: java.lang.Exception -> L58
            java.lang.Object r11 = kotlinx.coroutines.E.J(r11, r4, r0)     // Catch: java.lang.Exception -> L58
            if (r11 != r1) goto L50
            goto L52
        L50:
            kotlin.Unit r11 = kotlin.Unit.a     // Catch: java.lang.Exception -> L58
        L52:
            if (r11 != r1) goto L55
            return r1
        L55:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L58:
            r11 = r10
        L59:
            java.lang.Object r11 = r11.c
            org.slf4j.b r11 = (org.slf4j.b) r11
            java.lang.String r12 = "Exception in the CreateNewSchoolMembershipUseCase while creating school membership."
            r11.m(r12)
            com.quizlet.data.repository.school.exceptions.CreateNewSchoolMembershipException r11 = new com.quizlet.data.repository.school.exceptions.CreateNewSchoolMembershipException
            java.lang.String r12 = "Could not create school membership."
            r11.<init>(r12)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.school.b.m(long, com.quizlet.generated.enums.U1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(com.quizlet.data.model.C4179x0 r21, boolean r22, kotlin.coroutines.jvm.internal.c r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 301
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.school.b.n(com.quizlet.data.model.x0, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folder.p
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folder.p r0 = (com.quizlet.data.interactor.folder.p) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.p r0 = new com.quizlet.data.interactor.folder.p
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            long r5 = r0.k
            com.quizlet.data.interactor.school.b r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            goto L60
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.c
            java.util.LinkedHashMap r7 = (java.util.LinkedHashMap) r7
            java.lang.Long r2 = new java.lang.Long
            r2.<init>(r5)
            java.lang.Object r7 = r7.get(r2)
            java.util.List r7 = (java.util.List) r7
            if (r7 == 0) goto L4e
            kotlin.p r5 = kotlin.r.b
            return r7
        L4e:
            r0.j = r4
            r0.k = r5
            r0.n = r3
            java.lang.Object r7 = r4.b
            com.quizlet.data.repository.folder.i r7 = (com.quizlet.data.repository.folder.i) r7
            java.lang.Object r7 = r7.f(r5, r0)
            if (r7 != r1) goto L5f
            return r1
        L5f:
            r0 = r4
        L60:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r7 instanceof kotlin.q
            if (r1 != 0) goto L75
            r1 = r7
            java.util.List r1 = (java.util.List) r1
            java.lang.Long r2 = new java.lang.Long
            r2.<init>(r5)
            java.lang.Object r5 = r0.c
            java.util.LinkedHashMap r5 = (java.util.LinkedHashMap) r5
            r5.put(r2, r1)
        L75:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.school.b.o(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public /* synthetic */ b(int i, boolean z) {
        this.a = i;
    }

    public /* synthetic */ b(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public b(Context context) {
        this.a = 10;
        this.c = new AtomicLong(-1L);
        this.b = com.google.android.gms.common.internal.u.n(context, new k("mlkit:vision"));
    }

    public b(AbstractActivityC0055k abstractActivityC0055k) {
        this.a = 11;
        this.c = abstractActivityC0055k.getApplicationContext();
    }

    public b(AccessibilityManager accessibilityManager, EventLogger eventLogger) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(accessibilityManager, "accessibilityManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = accessibilityManager;
        this.c = eventLogger;
    }

    public b(com.quizlet.data.repository.activitycenter.b studySetWithCreatorInClassLocal, com.quizlet.remote.model.union.studysetwithcreatorinclass.e studySetWithCreatorInClassRemote) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(studySetWithCreatorInClassLocal, "studySetWithCreatorInClassLocal");
        Intrinsics.checkNotNullParameter(studySetWithCreatorInClassRemote, "studySetWithCreatorInClassRemote");
        this.b = studySetWithCreatorInClassLocal;
        this.c = studySetWithCreatorInClassRemote;
    }

    public b(com.quizlet.data.repository.folder.i folderRepository) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        this.b = folderRepository;
        this.c = new LinkedHashMap();
    }

    public b(com.quizlet.data.repository.user.a userRepository, androidx.work.impl.model.c dispatcher) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(userRepository, "userRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = userRepository;
        this.c = dispatcher;
    }

    public b(androidx.work.impl.model.c dataSource, com.quizlet.quizletandroid.k textbookMapper, com.quizlet.quizletandroid.logging.initializer.a meteringInfoMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(textbookMapper, "textbookMapper");
        Intrinsics.checkNotNullParameter(meteringInfoMapper, "meteringInfoMapper");
        this.b = dataSource;
        this.c = textbookMapper;
    }

    public b(com.quizlet.features.setpage.upsell.a explanationsUpsellPreferenceManager, androidx.work.impl.model.c userProps) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(explanationsUpsellPreferenceManager, "explanationsUpsellPreferenceManager");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        this.b = explanationsUpsellPreferenceManager;
        this.c = userProps;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                List list = (List) this.b;
                Intrinsics.d(list);
                Object obj2 = ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    arrayList.add(com.onetrust.otpublishers.headless.Internal.Helper.h.v((DBGroupFolder) it3.next()));
                }
                return arrayList;
            case EventType.AUDIO /* 23 */:
                List users = (List) obj;
                Intrinsics.checkNotNullParameter(users, "users");
                List list2 = (List) this.c;
                Intrinsics.d(list2);
                return com.quizlet.local.ormlite.models.studysetwithcreator.a.b((com.quizlet.local.ormlite.models.studysetwithcreator.a) this.b, list2, users);
            default:
                String imageUrl = (String) obj;
                Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
                com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar = (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) ((s) this.b).c;
                com.quizlet.qutils.data.offline.d dVar = ((com.quizlet.quizletandroid.data.management.a) this.c).b;
                return cVar.a(dVar.a(imageUrl, dVar.d));
        }
    }

    public b(com.quizlet.data.repository.set.f repository, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = repository;
        this.c = logger;
    }

    public b(com.quizlet.data.repository.metering.j repository, com.lyft.android.scissors.b syncUtil) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(syncUtil, "syncUtil");
        this.b = repository;
        this.c = syncUtil;
    }

    public b(com.quizlet.infra.legacysyncengine.managers.g livePreferencesManager, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(livePreferencesManager, "livePreferencesManager");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.b = livePreferencesManager;
        this.c = loggedInUserManager;
    }

    public b(com.quizlet.data.repository.explanations.exercise.b repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public b(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.infra.legacysyncengine.managers.i uiModelSaveManager) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(uiModelSaveManager, "uiModelSaveManager");
        this.b = loggedInUserManager;
        this.c = uiModelSaveManager;
    }

    public b(int i) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = new LinkedHashMap();
                this.c = new LinkedHashMap();
                break;
            case 14:
                com.perimeterx.mobile_sdk.detections.device.touch_interception.g gVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.g.a;
                this.b = com.perimeterx.mobile_sdk.detections.device.touch_interception.f.a;
                this.c = new HashMap();
                break;
            default:
                this.b = new Object();
                this.c = new LinkedHashMap();
                new HashSet();
                break;
        }
    }

    public b(androidx.camera.camera2.internal.C c) {
        this.a = 1;
        this.c = c;
        this.b = null;
    }
}

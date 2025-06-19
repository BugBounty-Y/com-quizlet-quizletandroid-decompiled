package com.quizlet.data.interactor.achievements;

import android.content.SharedPreferences;
import androidx.collection.C0204b;
import androidx.collection.C0209g;
import com.braze.models.cards.Card;
import com.google.android.gms.internal.ads.C3;
import com.j256.ormlite.dao.Dao;
import com.quizlet.data.model.C4135i0;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.generated.enums.I0;
import com.quizlet.quizletandroid.interactor.t;
import com.quizlet.quizletandroid.u;
import com.quizlet.uicommon.ui.common.dialogs.ConfirmationModalFragment;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import kotlin.collections.C;
import kotlin.coroutines.p;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public final class f implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.b, dagger.android.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.data.interactor.achievements.f r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof com.quizlet.data.interactor.achievements.e
            if (r0 == 0) goto L16
            r0 = r5
            com.quizlet.data.interactor.achievements.e r0 = (com.quizlet.data.interactor.achievements.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.l = r1
            goto L1b
        L16:
            com.quizlet.data.interactor.achievements.e r0 = new com.quizlet.data.interactor.achievements.e
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Exception -> L45
            goto L42
        L2a:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r4 = r4.b     // Catch: java.lang.Exception -> L45
            com.quizlet.data.repository.achievements.h r4 = (com.quizlet.data.repository.achievements.h) r4     // Catch: java.lang.Exception -> L45
            r0.l = r3     // Catch: java.lang.Exception -> L45
            java.lang.Object r5 = r4.b(r0)     // Catch: java.lang.Exception -> L45
            if (r5 != r1) goto L42
            return r1
        L42:
            com.quizlet.data.model.k r5 = (com.quizlet.data.model.AbstractC4140k) r5     // Catch: java.lang.Exception -> L45
            return r5
        L45:
            r4 = move-exception
            com.quizlet.data.model.i r5 = new com.quizlet.data.model.i
            r5.<init>(r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.a(com.quizlet.data.interactor.achievements.f, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0027  */
    @Override // io.reactivex.rxjava3.functions.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object apply(java.lang.Object r2, java.lang.Object r3) {
        /*
            r1 = this;
            java.lang.String r0 = "t"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r0)
            java.lang.String r0 = "u"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r0)
            java.lang.String r3 = (java.lang.String) r3
            java.lang.String r2 = (java.lang.String) r2
            kotlin.jvm.internal.Intrinsics.d(r2)
            java.lang.Object r0 = r1.b
            com.quizlet.featuregate.features.flexiblegrading.a r0 = (com.quizlet.featuregate.features.flexiblegrading.a) r0
            boolean r2 = com.quizlet.featuregate.features.flexiblegrading.a.a(r0, r2)
            if (r2 != 0) goto L27
            kotlin.jvm.internal.Intrinsics.d(r3)
            boolean r2 = com.quizlet.featuregate.features.flexiblegrading.a.a(r0, r3)
            if (r2 == 0) goto L25
            goto L27
        L25:
            r2 = 0
            goto L28
        L27:
            r2 = 1
        L28:
            java.lang.Boolean r2 = java.lang.Boolean.valueOf(r2)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.apply(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    public Object b(Set set, kotlin.coroutines.jvm.internal.c cVar) {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            I0 i0 = (I0) it2.next();
            Boolean bool = (Boolean) ((LinkedHashMap) ((com.quizlet.local.cache.caches.b) this.b).b).get(i0);
            if (bool != null) {
                linkedHashMap.put(i0, bool);
            }
        }
        return linkedHashMap;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(java.util.List r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.c
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.folderstudymaterial.c r0 = (com.quizlet.data.interactor.folderstudymaterial.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.c r0 = new com.quizlet.data.interactor.folderstudymaterial.c
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            java.lang.Object r6 = r4.b
            com.google.firebase.messaging.p r6 = (com.google.firebase.messaging.p) r6
            java.lang.Object r5 = r6.g(r5, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.c(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        ((ConfirmationModalFragment) obj).q = ((u) this.b).w();
    }

    public Object e(kotlin.coroutines.jvm.internal.i frame) throws Throwable {
        p pVar = new p(kotlin.coroutines.intrinsics.h.b(frame));
        ((com.quizlet.facebook.b) this.b).a(new com.quizlet.features.practicetest.results.viewmodel.e(pVar, 2));
        Object objA = pVar.a();
        if (objA == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objA;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(kotlin.coroutines.jvm.internal.c r11) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r11 instanceof com.quizlet.data.interactor.achievements.c
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.data.interactor.achievements.c r0 = (com.quizlet.data.interactor.achievements.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.achievements.c r0 = new com.quizlet.data.interactor.achievements.c
            r0.<init>(r10, r11)
        L18:
            java.lang.Object r11 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.interactor.achievements.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L4a
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            kotlinx.coroutines.scheduling.e r11 = kotlinx.coroutines.O.a
            kotlinx.coroutines.scheduling.d r11 = kotlinx.coroutines.scheduling.d.b
            com.quizlet.data.interactor.achievements.d r2 = new com.quizlet.data.interactor.achievements.d
            r4 = 0
            r2.<init>(r10, r4)
            r0.j = r10
            r0.m = r3
            java.lang.Object r11 = kotlinx.coroutines.E.J(r11, r2, r0)
            if (r11 != r1) goto L49
            return r1
        L49:
            r0 = r10
        L4a:
            com.quizlet.data.model.k r11 = (com.quizlet.data.model.AbstractC4140k) r11
            boolean r1 = r11 instanceof com.quizlet.data.model.C4131h
            if (r1 == 0) goto Lbf
            com.quizlet.data.model.h r11 = (com.quizlet.data.model.C4131h) r11
            r0.getClass()
            java.util.ArrayList r2 = new java.util.ArrayList
            r2.<init>()
            java.util.ArrayList r3 = new java.util.ArrayList
            r3.<init>()
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            java.util.ArrayList r6 = new java.util.ArrayList
            r6.<init>()
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            java.util.ArrayList r8 = new java.util.ArrayList
            r8.<init>()
            java.util.ArrayList r11 = r11.a
            java.util.Iterator r11 = r11.iterator()
        L7e:
            boolean r0 = r11.hasNext()
            if (r0 == 0) goto Lb9
            java.lang.Object r0 = r11.next()
            com.quizlet.data.model.a r0 = (com.quizlet.data.model.C4106a) r0
            com.quizlet.generated.enums.f r1 = r0.c
            int[] r9 = com.quizlet.data.interactor.achievements.b.a
            int r1 = r1.ordinal()
            r1 = r9[r1]
            switch(r1) {
                case 1: goto Lb5;
                case 2: goto Lb5;
                case 3: goto Lb1;
                case 4: goto Lb1;
                case 5: goto Lad;
                case 6: goto La9;
                case 7: goto La5;
                case 8: goto La1;
                case 9: goto L9d;
                default: goto L97;
            }
        L97:
            kotlin.NoWhenBranchMatchedException r11 = new kotlin.NoWhenBranchMatchedException
            r11.<init>()
            throw r11
        L9d:
            r8.add(r0)
            goto L7e
        La1:
            r2.add(r0)
            goto L7e
        La5:
            r7.add(r0)
            goto L7e
        La9:
            r6.add(r0)
            goto L7e
        Lad:
            r5.add(r0)
            goto L7e
        Lb1:
            r4.add(r0)
            goto L7e
        Lb5:
            r3.add(r0)
            goto L7e
        Lb9:
            com.quizlet.data.interactor.achievements.a r1 = new com.quizlet.data.interactor.achievements.a
            r1.<init>(r2, r3, r4, r5, r6, r7, r8)
            return r1
        Lbf:
            com.quizlet.data.interactor.achievements.a r2 = new com.quizlet.data.interactor.achievements.a
            kotlin.collections.K r3 = kotlin.collections.K.a
            r4 = r3
            r5 = r3
            r6 = r3
            r7 = r3
            r8 = r3
            r9 = r3
            r2.<init>(r3, r4, r5, r6, r7, r8, r9)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public Dao g() {
        Object value = ((kotlin.u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Dao) value;
    }

    public com.quizlet.qutils.language.e h(com.quizlet.features.infra.basestudy.manager.f studyModeManager) {
        com.quizlet.quizletandroid.util.f fVar = (com.quizlet.quizletandroid.util.f) this.b;
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        try {
            String wordLang = studyModeManager.x.f.getWordLang();
            String defLang = studyModeManager.x.f.getDefLang();
            Intrinsics.d(wordLang);
            Intrinsics.d(defLang);
            return fVar.f(wordLang, defLang);
        } catch (Exception unused) {
            return fVar.f("??", "??");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.notes.d
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.notes.d r0 = (com.quizlet.data.interactor.notes.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.notes.d r0 = new com.quizlet.data.interactor.notes.d
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L27
            goto L50
        L27:
            r5 = move-exception
            goto L53
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L27
            com.quizlet.remote.model.notes.e r6 = (com.quizlet.remote.model.notes.e) r6     // Catch: java.lang.Exception -> L27
            r0.l = r3     // Catch: java.lang.Exception -> L27
            com.quizlet.remote.model.notes.a r2 = new com.quizlet.remote.model.notes.a     // Catch: java.lang.Exception -> L27
            r3 = 0
            r2.<init>(r6, r5, r3)     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = r6.c     // Catch: java.lang.Exception -> L27
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Exception -> L27
            if (r5 != r1) goto L4b
            goto L4d
        L4b:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Exception -> L27
        L4d:
            if (r5 != r1) goto L50
            return r1
        L50:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L53:
            com.quizlet.data.exceptions.notes.DeleteNoteException r6 = new com.quizlet.data.exceptions.notes.DeleteNoteException
            java.lang.String r5 = r5.getMessage()
            r6.<init>(r5)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.i(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(com.quizlet.db.data.models.persisted.DBUser r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.login.common.interactors.l
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.login.common.interactors.l r0 = (com.quizlet.login.common.interactors.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.l r0 = new com.quizlet.login.common.interactors.l
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L27
            goto L49
        L27:
            r5 = move-exception
            goto L50
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.billing.model.b r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3714r6.b(r5)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L27
            com.quizlet.billing.subscriptions.i r6 = (com.quizlet.billing.subscriptions.i) r6     // Catch: java.lang.Exception -> L27
            io.reactivex.rxjava3.internal.operators.observable.g r5 = r6.b(r5)     // Catch: java.lang.Exception -> L27
            r0.l = r3     // Catch: java.lang.Exception -> L27
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)     // Catch: java.lang.Exception -> L27
            if (r6 != r1) goto L49
            return r1
        L49:
            java.lang.Boolean r6 = (java.lang.Boolean) r6     // Catch: java.lang.Exception -> L27
            boolean r5 = r6.booleanValue()     // Catch: java.lang.Exception -> L27
            goto L56
        L50:
            timber.log.a r6 = timber.log.c.a
            r6.e(r5)
            r5 = 0
        L56:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.j(com.quizlet.db.data.models.persisted.DBUser, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.interactor.school.g
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.interactor.school.g r0 = (com.quizlet.data.interactor.school.g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.school.g r0 = new com.quizlet.data.interactor.school.g
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L27
            goto L4d
        L27:
            r5 = move-exception
            goto L52
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r4.b     // Catch: java.lang.Throwable -> L27
            com.quizlet.data.repository.set.f r5 = (com.quizlet.data.repository.set.f) r5     // Catch: java.lang.Throwable -> L27
            r0.l = r3     // Catch: java.lang.Throwable -> L27
            com.quizlet.remote.model.school.e r2 = new com.quizlet.remote.model.school.e     // Catch: java.lang.Throwable -> L27
            r3 = 0
            r2.<init>(r5, r3)     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r5.d     // Catch: java.lang.Throwable -> L27
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Throwable -> L27
            if (r5 != r1) goto L4d
            return r1
        L4d:
            com.quizlet.data.model.x1 r5 = (com.quizlet.data.model.C4180x1) r5     // Catch: java.lang.Throwable -> L27
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            return r5
        L52:
            kotlin.p r0 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.course.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.course.f r0 = (com.quizlet.data.interactor.course.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.course.f r0 = new com.quizlet.data.interactor.course.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L27
            goto L4d
        L27:
            r5 = move-exception
            goto L52
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.p r7 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            java.lang.Object r7 = r4.b     // Catch: java.lang.Throwable -> L27
            androidx.work.impl.model.n r7 = (androidx.work.impl.model.n) r7     // Catch: java.lang.Throwable -> L27
            r0.l = r3     // Catch: java.lang.Throwable -> L27
            com.quizlet.remote.model.course.h r2 = new com.quizlet.remote.model.course.h     // Catch: java.lang.Throwable -> L27
            r3 = 0
            r2.<init>(r7, r5, r3)     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r7.d     // Catch: java.lang.Throwable -> L27
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Throwable -> L27
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Throwable -> L27
            if (r7 != r1) goto L4d
            return r1
        L4d:
            com.quizlet.data.model.L r7 = (com.quizlet.data.model.L) r7     // Catch: java.lang.Throwable -> L27
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            return r7
        L52:
            kotlin.p r6 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.l(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public ArrayList m() {
        List<String> list = (List) this.b;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (String source : list) {
            List list2 = com.quizlet.generated.deeplinkpaths.a.a;
            Intrinsics.checkNotNullParameter(source, "source");
            arrayList.add(Pattern.compile(new Regex("(?<=\\/)\\*").replace(source, "[a-zA-Z0-9_\\\\-\\\\/]*")));
        }
        return arrayList;
    }

    public void n(ArrayList cards) {
        Intrinsics.checkNotNullParameter(cards, "cards");
        SharedPreferences sharedPreferences = ((com.quizlet.quizletandroid.ui.activitycenter.managers.b) this.b).a;
        Set<String> setKeySet = sharedPreferences.getAll().keySet();
        ArrayList arrayList = new ArrayList();
        for (Object obj : setKeySet) {
            if (StringsKt.G((String) obj, "CAMPAIGN_ID_KEY_PREFIX_", false)) {
                arrayList.add(obj);
            }
        }
        C0209g c0209g = new C0209g(0);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            Intrinsics.d(str);
            c0209g.add(StringsKt.T(str, "CAMPAIGN_ID_KEY_PREFIX_"));
        }
        if (c0209g.isEmpty()) {
            return;
        }
        C0209g campaignIdsToRemove = new C0209g(0);
        ArrayList arrayList2 = new ArrayList();
        Iterator it3 = cards.iterator();
        while (it3.hasNext()) {
            Object next = it3.next();
            Card card = (Card) next;
            Intrinsics.checkNotNullParameter(card, "<this>");
            String str2 = card.getExtras().get("campaignId");
            if (str2 != null ? c0209g.contains(str2) : false) {
                arrayList2.add(next);
            }
        }
        Iterator it4 = arrayList2.iterator();
        while (it4.hasNext()) {
            Card card2 = (Card) it4.next();
            card2.logClick();
            card2.setIndicatorHighlighted(true);
            card2.setViewed(true);
            Intrinsics.checkNotNullParameter(card2, "<this>");
            String str3 = card2.getExtras().get("campaignId");
            if (str3 != null) {
                campaignIdsToRemove.add(str3);
            }
        }
        Intrinsics.checkNotNullParameter(campaignIdsToRemove, "campaignIdsToRemove");
        C0209g c0209g2 = new C0209g(0);
        C0204b c0204b = new C0204b(campaignIdsToRemove);
        while (c0204b.hasNext()) {
            c0209g2.add("CAMPAIGN_ID_KEY_PREFIX_" + ((String) c0204b.next()));
        }
        Map<String, ?> all = sharedPreferences.getAll();
        Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            Long l = value instanceof Long ? (Long) value : null;
            long jLongValue = l != null ? l.longValue() : -1L;
            Intrinsics.d(key);
            if (StringsKt.G(key, "CAMPAIGN_ID_KEY_PREFIX_", false) && System.currentTimeMillis() - jLongValue > com.quizlet.quizletandroid.ui.activitycenter.managers.b.b) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        c0209g2.addAll(linkedHashMap.keySet());
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        C0204b c0204b2 = new C0204b(c0209g2);
        while (c0204b2.hasNext()) {
            editorEdit.remove((String) c0204b2.next());
        }
        editorEdit.apply();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(java.util.List r8, kotlin.coroutines.jvm.internal.c r9) throws java.sql.SQLException {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.local.ormlite.database.dao.d
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.local.ormlite.database.dao.d r0 = (com.quizlet.local.ormlite.database.dao.d) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.local.ormlite.database.dao.d r0 = new com.quizlet.local.ormlite.database.dao.d
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            java.util.List r8 = r0.k
            com.quizlet.data.interactor.achievements.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto La4
        L2c:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.util.ArrayList r9 = new java.util.ArrayList
            r9.<init>()
            java.util.ArrayList r2 = new java.util.ArrayList
            r2.<init>()
            java.util.Iterator r8 = r8.iterator()
        L45:
            boolean r4 = r8.hasNext()
            if (r4 == 0) goto L60
            java.lang.Object r4 = r8.next()
            r5 = r4
            com.quizlet.db.data.models.persisted.DBSelectedTerm r5 = (com.quizlet.db.data.models.persisted.DBSelectedTerm) r5
            boolean r5 = r5.getDeleted()
            if (r5 == 0) goto L5c
            r9.add(r4)
            goto L45
        L5c:
            r2.add(r4)
            goto L45
        L60:
            java.util.ArrayList r8 = new java.util.ArrayList
            r8.<init>()
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            java.util.Iterator r9 = r9.iterator()
        L6e:
            boolean r5 = r9.hasNext()
            if (r5 == 0) goto L89
            java.lang.Object r5 = r9.next()
            r6 = r5
            com.quizlet.db.data.models.persisted.DBSelectedTerm r6 = (com.quizlet.db.data.models.persisted.DBSelectedTerm) r6
            boolean r6 = r6.getDirty()
            if (r6 == 0) goto L85
            r8.add(r5)
            goto L6e
        L85:
            r4.add(r5)
            goto L6e
        L89:
            com.j256.ormlite.dao.Dao r9 = r7.g()
            java.util.ArrayList r8 = kotlin.collections.CollectionsKt.c0(r2, r8)
            io.reactivex.rxjava3.internal.operators.completable.c r8 = com.quizlet.local.ormlite.util.b.a(r9, r8)
            r0.j = r7
            r0.k = r4
            r0.n = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r8, r0)
            if (r8 != r1) goto La2
            return r1
        La2:
            r0 = r7
            r8 = r4
        La4:
            com.j256.ormlite.dao.Dao r9 = r0.g()
            r9.delete(r8)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.o(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean p() {
        DBUser dBUser = ((t) this.b).a.r;
        C4135i0 c4135i0S = dBUser != null ? retrofit2.adapter.rxjava3.d.s(dBUser) : null;
        if (c4135i0S != null) {
            return !c4135i0S.w || c4135i0S.n;
        }
        return false;
    }

    public f(List strings) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(strings, "strings");
        this.b = strings;
    }

    public f(C3 practiceTestsRepository) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    /*  JADX ERROR: NullPointerException in pass: InitCodeVariables
        java.lang.NullPointerException
        */
    @Override // io.reactivex.rxjava3.functions.h
    public java.lang.Object apply(java.lang.Object r21) {
        /*
            Method dump skipped, instructions count: 700
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.f.apply(java.lang.Object):java.lang.Object");
    }

    public f(com.quizlet.data.interactor.school.b textbookRemoteDataStore) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(textbookRemoteDataStore, "textbookRemoteDataStore");
        this.b = textbookRemoteDataStore;
    }

    public f(com.quizlet.local.cache.caches.b dataStore) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public f(com.quizlet.remote.model.notes.e notesRepository) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(notesRepository, "notesRepository");
        this.b = notesRepository;
    }

    public f(androidx.work.impl.model.n repository) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public f(com.google.firebase.messaging.p deleteFolderStudyMaterialRepository) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(deleteFolderStudyMaterialRepository, "deleteFolderStudyMaterialRepository");
        this.b = deleteFolderStudyMaterialRepository;
    }

    public f(com.quizlet.data.repository.set.f repository) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public f(com.quizlet.data.repository.user.e userRepository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(userRepository, "userRepository");
        this.b = userRepository;
    }

    public f(com.quizlet.facebook.b facebookSdkInitializer) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(facebookSdkInitializer, "facebookSdkInitializer");
        this.b = facebookSdkInitializer;
    }

    public f(com.quizlet.quizletandroid.util.f languageUtil) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        this.b = languageUtil;
    }

    public f(com.quizlet.billing.subscriptions.i subscriptionLookup) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(subscriptionLookup, "subscriptionLookup");
        this.b = subscriptionLookup;
    }

    public f(t loggedInUserInteractor) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        this.b = loggedInUserInteractor;
    }

    public f(com.quizlet.billing.register.a modeSharedPreferencesManager) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(modeSharedPreferencesManager, "modeSharedPreferencesManager");
        this.b = modeSharedPreferencesManager;
    }

    public f(com.quizlet.quizletandroid.ui.activitycenter.managers.b sharedPreferences) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        this.b = sharedPreferences;
    }

    public f(com.quizlet.data.repository.achievements.h repository) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public f(DatabaseHelper database) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 6));
    }

    public f(EventLogger eventLogger) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = eventLogger;
    }
}

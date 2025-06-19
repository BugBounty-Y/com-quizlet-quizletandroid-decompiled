package com.quizlet.data.repository.course.membership;

import android.database.sqlite.SQLiteDatabase;
import android.util.Log;
import android.view.ViewGroup;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.RunnableC0146x;
import androidx.camera.camera2.internal.a0;
import androidx.collection.I;
import androidx.compose.animation.d0;
import androidx.compose.runtime.saveable.h;
import androidx.constraintlayout.core.widgets.e;
import androidx.constraintlayout.core.widgets.f;
import androidx.lifecycle.m0;
import assistantMode.types.w;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.gtm.zzbu;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_common.C3443e;
import com.google.android.gms.internal.mlkit_vision_common.C3449f;
import com.google.android.gms.internal.mlkit_vision_common.C3483k3;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.google.android.material.floatingactionbutton.g;
import com.google.common.collect.C3922e;
import com.google.common.collect.j;
import com.google.firebase.encoders.EncodingException;
import com.google.gson.internal.d;
import com.google.gson.internal.n;
import com.google.gson.internal.o;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.support.ConnectionSource;
import com.quizlet.data.model.ExerciseDetails;
import com.quizlet.data.model.Textbook;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.learn.data.onboarding.q;
import com.quizlet.learn.data.onboarding.t;
import com.quizlet.learn.data.onboarding.v;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.quizletandroid.k;
import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import com.quizlet.quizletandroid.ui.common.ads.C4637d;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.core.p;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.AbstractC5040y;
import org.jsoup.parser.C;
import org.jsoup.parser.f1;

/* loaded from: classes2.dex */
public class c implements h, g, n, io.reactivex.rxjava3.functions.h, com.quizlet.remote.mapper.base.a {
    public final Object a;
    public final Object b;
    public Object c;

    public /* synthetic */ c(Object obj, Object obj2, Object obj3) {
        this.c = obj;
        this.a = obj2;
        this.b = obj3;
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        try {
            return ((d) this.a).i((Class) this.b);
        } catch (Exception e) {
            throw new RuntimeException("Unable to invoke no-args constructor for " + ((Type) this.c) + ". Registering an InstanceCreator with Gson for this type may fix this problem.", e);
        }
    }

    public Object a() {
        Object objA = ((androidx.core.util.d) this.c).a();
        if (objA == null) {
            objA = ((com.bumptech.glide.util.pool.a) this.a).c();
            if (Log.isLoggable("FactoryPools", 2)) {
                objA.getClass().toString();
            }
        }
        if (objA instanceof com.bumptech.glide.util.pool.b) {
            ((com.bumptech.glide.util.pool.b) objA).b().a = false;
        }
        return objA;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Boolean imageResults = (Boolean) obj;
        Intrinsics.checkNotNullParameter(imageResults, "imageResults");
        timber.log.a aVar = timber.log.c.a;
        com.quizlet.quizletandroid.data.management.a aVar2 = (com.quizlet.quizletandroid.data.management.a) this.a;
        aVar.a(d0.o(aVar2.a.getId(), "Asset collection for ", " :"), new Object[0]);
        aVar.a("\t%s of %s image files successfully downloaded: %s", String.valueOf(((List) this.b).size()), String.valueOf(((HashSet) this.c).size()), String.valueOf(imageResults.booleanValue()));
        return aVar2;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int b() {
        int i = ((ExtendedFloatingActionButton) this.c).H;
        return i == -1 ? ((com.quizlet.data.repository.explanations.myexplanations.a) this.a).b() : (i == 0 || i == -2) ? ((ExtendedFloatingActionButton) ((com.google.android.material.floatingactionbutton.c) this.b).b).getMeasuredHeight() : i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0097, code lost:
    
        if (r8 == r1) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(kotlin.coroutines.h r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.featuregate.features.folder.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.featuregate.features.folder.c r0 = (com.quizlet.featuregate.features.folder.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.folder.c r0 = new com.quizlet.featuregate.features.folder.c
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L41
            if (r2 == r5) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L9a
        L2d:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L35:
            com.quizlet.data.repository.course.membership.c r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7e
        L3b:
            com.quizlet.data.repository.course.membership.c r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L58
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r7
            r0.m = r5
            java.lang.Object r8 = r7.a
            com.quizlet.data.repository.login.a r8 = (com.quizlet.data.repository.login.a) r8
            java.lang.Object r2 = r7.b
            androidx.work.impl.model.c r2 = (androidx.work.impl.model.c) r2
            java.lang.Object r8 = r8.b(r2, r0)
            if (r8 != r1) goto L57
            goto L99
        L57:
            r2 = r7
        L58:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto La3
            java.lang.Object r8 = r2.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.y()
            com.quizlet.featuregate.contracts.properties.d r6 = com.quizlet.featuregate.contracts.properties.d.b
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.g(r6)
            java.lang.String r6 = "map(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r6)
            r0.j = r2
            r0.m = r4
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L7e
            goto L99
        L7e:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto La3
            java.lang.Object r8 = r2.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.u()
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r8, r0)
            if (r8 != r1) goto L9a
        L99:
            return r1
        L9a:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto La3
            goto La4
        La3:
            r5 = 0
        La4:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r5)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.course.membership.c.d(kotlin.coroutines.h):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    public com.quizlet.features.match.logging.b f(m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        return new com.quizlet.features.match.logging.b(((com.quizlet.features.infra.basestudy.manager.a) this.a).a(savedStateHandle), (com.quizlet.features.match.logging.a) this.b, (EventLogger) this.c);
    }

    public Object g(Object obj) {
        C4637d input = (C4637d) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        int i = input.a;
        com.quizlet.shared.usecase.studiableMetadata.a aVar = (com.quizlet.shared.usecase.studiableMetadata.a) this.a;
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) this.b;
        p pVarP = p.p(aVar.l(cVar), cVar.o(new C4566c0(27), Boolean.FALSE), new C0122z(i, input.b, this));
        Intrinsics.checkNotNullExpressionValue(pVarP, "zip(...)");
        return pVarP;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public ViewGroup.LayoutParams getLayoutParams() {
        ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) this.c;
        int i = extendedFloatingActionButton.G;
        if (i == 0) {
            i = -2;
        }
        int i2 = extendedFloatingActionButton.H;
        return new ViewGroup.LayoutParams(i, i2 != 0 ? i2 : -2);
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int getWidth() {
        int i = ((ExtendedFloatingActionButton) this.c).G;
        return i == -1 ? ((com.quizlet.data.repository.explanations.myexplanations.a) this.a).getWidth() : (i == 0 || i == -2) ? ((com.google.android.material.floatingactionbutton.c) this.b).getWidth() : i;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(kotlin.coroutines.jvm.internal.c r5) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.repository.course.membership.a
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.repository.course.membership.a r0 = (com.quizlet.data.repository.course.membership.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.course.membership.a r0 = new com.quizlet.data.repository.course.membership.a
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.data.repository.course.membership.b r5 = new com.quizlet.data.repository.course.membership.b
            r2 = 0
            r5.<init>(r4, r2)
            r0.l = r3
            java.lang.Object r2 = r4.c
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r5 = kotlinx.coroutines.E.J(r2, r5, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            java.lang.String r0 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r0)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.course.membership.c.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int i() {
        return ((ExtendedFloatingActionButton) this.c).A;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(com.quizlet.generated.enums.G1 r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            r0 = 2
            r1 = 1
            r2 = 0
            boolean r3 = r9 instanceof com.quizlet.learn.usecase.onboarding.a
            if (r3 == 0) goto L16
            r3 = r9
            com.quizlet.learn.usecase.onboarding.a r3 = (com.quizlet.learn.usecase.onboarding.a) r3
            int r4 = r3.n
            r5 = -2147483648(0xffffffff80000000, float:-0.0)
            r6 = r4 & r5
            if (r6 == 0) goto L16
            int r4 = r4 - r5
            r3.n = r4
            goto L1b
        L16:
            com.quizlet.learn.usecase.onboarding.a r3 = new com.quizlet.learn.usecase.onboarding.a
            r3.<init>(r7, r9)
        L1b:
            java.lang.Object r9 = r3.l
            kotlin.coroutines.intrinsics.a r4 = kotlin.coroutines.intrinsics.a.a
            int r5 = r3.n
            if (r5 == 0) goto L35
            if (r5 != r1) goto L2d
            int r8 = r3.k
            com.quizlet.data.repository.course.membership.c r3 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L51
        L2d:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.generated.enums.G1 r9 = com.quizlet.generated.enums.G1.FOLDER
            if (r8 != r9) goto L3e
            r8 = r1
            goto L3f
        L3e:
            r8 = r2
        L3f:
            r3.j = r7
            r3.k = r8
            r3.n = r1
            java.lang.Object r9 = r7.a
            com.quizlet.data.repository.folderwithcreator.e r9 = (com.quizlet.data.repository.folderwithcreator.e) r9
            java.lang.Object r9 = r9.j(r3)
            if (r9 != r4) goto L50
            return r4
        L50:
            r3 = r7
        L51:
            com.quizlet.featuregate.contracts.enums.b r9 = (com.quizlet.featuregate.contracts.enums.b) r9
            int r9 = r9.ordinal()
            if (r9 == 0) goto L9b
            r4 = 2132018486(0x7f140536, float:1.967528E38)
            if (r9 == r1) goto L89
            r5 = 0
            if (r9 == r0) goto L78
            r0 = 3
            if (r9 != r0) goto L72
            com.quizlet.learn.data.onboarding.c r9 = new com.quizlet.learn.data.onboarding.c
            java.lang.Object r0 = r3.c
            com.quizlet.learn.data.onboarding.v r0 = (com.quizlet.learn.data.onboarding.v) r0
            if (r8 != 0) goto L6d
            goto L6e
        L6d:
            r1 = r2
        L6e:
            r9.<init>(r4, r5, r0, r1)
            return r9
        L72:
            kotlin.NoWhenBranchMatchedException r8 = new kotlin.NoWhenBranchMatchedException
            r8.<init>()
            throw r8
        L78:
            com.quizlet.learn.data.onboarding.c r9 = new com.quizlet.learn.data.onboarding.c
            java.lang.Object r0 = r3.b
            com.quizlet.learn.data.onboarding.n r0 = (com.quizlet.learn.data.onboarding.n) r0
            if (r8 != 0) goto L81
            goto L82
        L81:
            r1 = r2
        L82:
            r8 = 2132018472(0x7f140528, float:1.9675252E38)
            r9.<init>(r8, r0, r5, r1)
            return r9
        L89:
            com.quizlet.learn.data.onboarding.c r9 = new com.quizlet.learn.data.onboarding.c
            java.lang.Object r0 = r3.b
            com.quizlet.learn.data.onboarding.n r0 = (com.quizlet.learn.data.onboarding.n) r0
            if (r8 != 0) goto L92
            goto L93
        L92:
            r1 = r2
        L93:
            java.lang.Object r8 = r3.c
            com.quizlet.learn.data.onboarding.v r8 = (com.quizlet.learn.data.onboarding.v) r8
            r9.<init>(r4, r0, r8, r1)
            return r9
        L9b:
            com.quizlet.learn.data.onboarding.a r9 = new com.quizlet.learn.data.onboarding.a
            com.quizlet.learn.data.onboarding.m[] r0 = new com.quizlet.learn.data.onboarding.m[r0]
            com.quizlet.learn.data.onboarding.l r3 = com.quizlet.learn.data.onboarding.l.d
            r0[r2] = r3
            com.quizlet.learn.data.onboarding.k r3 = com.quizlet.learn.data.onboarding.k.d
            r0[r1] = r3
            kotlinx.collections.immutable.e r0 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.h(r0)
            if (r8 != 0) goto Lae
            goto Laf
        Lae:
            r1 = r2
        Laf:
            r9.<init>(r0, r1)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.course.membership.c.j(com.quizlet.generated.enums.G1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: k, reason: merged with bridge method [inline-methods] */
    public ExerciseDetails c(RemoteExerciseDetails remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        Textbook textbookQ = ((k) this.b).c(remote.k);
        ArrayList arrayListF = S.f((com.quizlet.quizletandroid.ui.common.images.capture.a) this.c, remote.l);
        com.quizlet.quizletandroid.ui.common.images.capture.b bVar = (com.quizlet.quizletandroid.ui.common.images.capture.b) this.a;
        ArrayList arrayListF2 = T.f(bVar, remote.m);
        ArrayList arrayListF3 = T.f(bVar, remote.n);
        return new ExerciseDetails(j, remote.b, remote.c, remote.d, remote.f, remote.g, remote.e, remote.h, remote.i, textbookQ, arrayListF, arrayListF2, arrayListF3, remote.j);
    }

    public boolean l(int i, e eVar, androidx.constraintlayout.core.widgets.analyzer.c cVar) {
        androidx.constraintlayout.core.widgets.d[] dVarArr = eVar.V;
        androidx.constraintlayout.core.widgets.d dVar = dVarArr[0];
        androidx.constraintlayout.core.widgets.analyzer.b bVar = (androidx.constraintlayout.core.widgets.analyzer.b) this.b;
        bVar.a = dVar;
        bVar.b = dVarArr[1];
        bVar.c = eVar.r();
        bVar.d = eVar.l();
        bVar.i = false;
        bVar.j = i;
        androidx.constraintlayout.core.widgets.d dVar2 = bVar.a;
        androidx.constraintlayout.core.widgets.d dVar3 = androidx.constraintlayout.core.widgets.d.c;
        boolean z = dVar2 == dVar3;
        boolean z2 = bVar.b == dVar3;
        boolean z3 = z && eVar.Z > DefinitionKt.NO_Float_VALUE;
        boolean z4 = z2 && eVar.Z > DefinitionKt.NO_Float_VALUE;
        androidx.constraintlayout.core.widgets.d dVar4 = androidx.constraintlayout.core.widgets.d.a;
        int[] iArr = eVar.u;
        if (z3 && iArr[0] == 4) {
            bVar.a = dVar4;
        }
        if (z4 && iArr[1] == 4) {
            bVar.b = dVar4;
        }
        cVar.b(eVar, bVar);
        eVar.S(bVar.e);
        eVar.N(bVar.f);
        eVar.F = bVar.h;
        eVar.J(bVar.g);
        bVar.j = 0;
        return bVar.i;
    }

    public void m(SQLiteDatabase sQLiteDatabase, ConnectionSource connectionSource, int i, int i2) {
        com.quizlet.data.interactor.progress.c cVar = new com.quizlet.data.interactor.progress.c(sQLiteDatabase, (OrmLiteSqliteOpenHelper) this.a, connectionSource, (com.google.firebase.messaging.p) this.b);
        C3922e c3922eListIterator = ((j) this.c).listIterator(0);
        while (c3922eListIterator.hasNext()) {
            com.quizlet.android.migrator.migrations.a aVar = (com.quizlet.android.migrator.migrations.a) c3922eListIterator.next();
            int iIntValue = aVar.getVersion().intValue();
            boolean z = i < iIntValue && iIntValue <= i2;
            boolean z2 = aVar.getVersion().intValue() > i2;
            if (z) {
                aVar.b(aVar.a(cVar));
            }
            if (!z2) {
                aVar.c(aVar.a(cVar));
            }
        }
    }

    public org.jsoup.nodes.g n(String str, String str2) {
        StringReader stringReader = new StringReader(str);
        f1 f1Var = (f1) this.a;
        f1Var.d(stringReader, str2, this);
        f1Var.h();
        f1Var.b.d();
        f1Var.b = null;
        f1Var.c = null;
        f1Var.e = null;
        f1Var.i = null;
        return f1Var.d;
    }

    public boolean o(Object obj) {
        if (obj instanceof com.bumptech.glide.util.pool.b) {
            ((com.bumptech.glide.util.pool.b) obj).b().a = true;
        }
        ((com.bumptech.glide.util.pool.c) this.b).k(obj);
        return ((androidx.core.util.d) this.c).c(obj);
    }

    public void p(f fVar, int i, int i2, int i3) {
        fVar.getClass();
        int i4 = fVar.e0;
        int i5 = fVar.f0;
        fVar.e0 = 0;
        fVar.f0 = 0;
        fVar.S(i2);
        fVar.N(i3);
        if (i4 < 0) {
            fVar.e0 = 0;
        } else {
            fVar.e0 = i4;
        }
        if (i5 < 0) {
            fVar.f0 = 0;
        } else {
            fVar.f0 = i5;
        }
        f fVar2 = (f) this.c;
        fVar2.w0 = i;
        fVar2.Z();
    }

    public void q() {
        I i = (I) this.a;
        String str = (String) this.b;
        List list = (List) i.h(str);
        if (list != null) {
            list.remove((r) this.c);
        }
        if (list == null || list.isEmpty()) {
            return;
        }
        i.j(str, list);
    }

    public void r(f fVar) {
        ArrayList arrayList = (ArrayList) this.a;
        arrayList.clear();
        int size = fVar.t0.size();
        for (int i = 0; i < size; i++) {
            e eVar = (e) fVar.t0.get(i);
            androidx.constraintlayout.core.widgets.d[] dVarArr = eVar.V;
            androidx.constraintlayout.core.widgets.d dVar = dVarArr[0];
            androidx.constraintlayout.core.widgets.d dVar2 = androidx.constraintlayout.core.widgets.d.c;
            if (dVar == dVar2 || dVarArr[1] == dVar2) {
                arrayList.add(eVar);
            }
        }
        fVar.v0.b = true;
    }

    public byte[] s(C3483k3 c3483k3) {
        C3449f c3449f;
        com.google.firebase.encoders.c cVar;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            HashMap map = (HashMap) this.a;
            c3449f = new C3449f(byteArrayOutputStream, map, (HashMap) this.b, (C3443e) this.c);
            cVar = (com.google.firebase.encoders.c) map.get(C3483k3.class);
        } catch (IOException unused) {
        }
        if (cVar == null) {
            throw new EncodingException("No encoder for ".concat(String.valueOf(C3483k3.class)));
        }
        cVar.a(c3483k3, c3449f);
        return byteArrayOutputStream.toByteArray();
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int v() {
        return ((ExtendedFloatingActionButton) this.c).z;
    }

    public /* synthetic */ c(boolean z, Object obj, Object obj2, Object obj3) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
    }

    public c(zzbu zzbuVar) {
        com.google.android.gms.analytics.j jVarZzd = zzbuVar.zzd();
        com.google.android.gms.common.util.a aVarZzr = zzbuVar.zzr();
        u.h(jVarZzd);
        this.b = new ArrayList();
        this.a = new androidx.work.impl.model.e(this, aVarZzr);
        this.c = zzbuVar;
    }

    public c(i dataSource, com.quizlet.quizletandroid.ui.activitycenter.models.a mapper, com.quizlet.quizletandroid.ui.folder.logging.a pagingMapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(pagingMapper, "pagingMapper");
        this.a = dataSource;
        this.b = mapper;
        this.c = pagingMapper;
    }

    public c(com.quizlet.quizletandroid.ui.common.images.capture.b remoteExerciseMapper, k remoteTextbookMapper, com.quizlet.quizletandroid.ui.common.images.capture.a remoteSolutionMapper) {
        Intrinsics.checkNotNullParameter(remoteExerciseMapper, "remoteExerciseMapper");
        Intrinsics.checkNotNullParameter(remoteTextbookMapper, "remoteTextbookMapper");
        Intrinsics.checkNotNullParameter(remoteSolutionMapper, "remoteSolutionMapper");
        this.a = remoteExerciseMapper;
        this.b = remoteTextbookMapper;
        this.c = remoteSolutionMapper;
    }

    public c(com.quizlet.quizletandroid.managers.upgrade.a settingsValidator, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(settingsValidator, "settingsValidator");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = settingsValidator;
        this.b = syncDispatcher;
        this.c = eventLogger;
    }

    public c(com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature, androidx.work.impl.model.c userProperties, com.quizlet.data.connectivity.a networkConnectivityManager) {
        Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
        this.a = globalAdFeature;
        this.b = userProperties;
        this.c = networkConnectivityManager;
    }

    public c(AbstractC5040y dispatcher, com.quizlet.data.repository.login.a usConstrainedFeature, androidx.work.impl.model.c userProperties) {
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(usConstrainedFeature, "usConstrainedFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.c = dispatcher;
        this.a = usConstrainedFeature;
        this.b = userProperties;
    }

    public c(com.quizlet.data.repository.folderwithcreator.e simplerOnboardingFeature) {
        Intrinsics.checkNotNullParameter(simplerOnboardingFeature, "simplerOnboardingFeature");
        this.a = simplerOnboardingFeature;
        com.quizlet.learn.data.onboarding.k kVar = com.quizlet.learn.data.onboarding.k.d;
        this.b = new com.quizlet.learn.data.onboarding.n(AbstractC3409x1.h(com.quizlet.learn.data.onboarding.j.d, kVar), kVar);
        t tVar = t.d;
        this.c = new v(AbstractC3409x1.h(com.quizlet.learn.data.onboarding.p.d, tVar, q.d), tVar);
    }

    public c(w roundOutline, assistantMode.utils.h studyableMaterialDataSource, ArrayList validCards) {
        Intrinsics.checkNotNullParameter(roundOutline, "roundOutline");
        Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
        Intrinsics.checkNotNullParameter(validCards, "validCards");
        this.a = studyableMaterialDataSource;
        this.b = validCards;
        this.c = new com.quizlet.data.repository.classfolder.e(roundOutline);
    }

    public c(com.quizlet.quizletandroid.ui.setcreation.managers.n remote, org.slf4j.b logger, AbstractC5040y dispatcher) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.a = remote;
        this.b = logger;
        this.c = dispatcher;
    }

    public c(f1 f1Var) {
        this.a = f1Var;
        this.c = f1Var.c();
        this.b = new C(0, 0);
    }

    public c(OrmLiteSqliteOpenHelper ormLiteSqliteOpenHelper, LinkedHashSet linkedHashSet, com.quizlet.android.migrator.migrations.a... aVarArr) {
        int iIntValue;
        this.a = ormLiteSqliteOpenHelper;
        this.b = new com.google.firebase.messaging.p(linkedHashSet, 4);
        List listAsList = Arrays.asList(aVarArr);
        Collections.sort(listAsList, new a0(18));
        if (listAsList.size() > 1) {
            int i = 0;
            while (i < listAsList.size() - 1) {
                com.quizlet.android.migrator.migrations.a aVar = (com.quizlet.android.migrator.migrations.a) listAsList.get(i);
                i++;
                com.quizlet.android.migrator.migrations.a aVar2 = (com.quizlet.android.migrator.migrations.a) listAsList.get(i);
                if (aVar.getVersion().equals(aVar2.getVersion())) {
                    throw new RuntimeException(String.format("Specified same version (%s) for migrations %s and %s", aVar.getVersion(), aVar, aVar2));
                }
            }
        }
        j jVarM = j.m(listAsList);
        this.c = jVarM;
        if (jVarM.size() > 0 && (iIntValue = ((com.quizlet.android.migrator.migrations.a) jVarM.get(jVarM.size() - 1)).getVersion().intValue()) != 114) {
            throw new IllegalStateException(AbstractC0147y.c(iIntValue, "Last migration version (", ") does not match CURRENT_DATABASE_VERSION (114)"));
        }
    }

    public c(com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.quizlet.features.match.logging.a questionEventLogger, EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(questionEventLogger, "questionEventLogger");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = studyModeManagerFactory;
        this.b = questionEventLogger;
        this.c = eventLogger;
    }

    public c(f fVar) {
        this.a = new ArrayList();
        this.b = new androidx.constraintlayout.core.widgets.analyzer.b();
        this.c = fVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public c(I i, String str, Function0 function0) {
        this.a = i;
        this.b = str;
        this.c = (r) function0;
    }

    public c(Class cls, Type type) throws NoSuchFieldException, NoSuchMethodException, ClassNotFoundException, SecurityException {
        Object rVar;
        this.b = cls;
        this.c = type;
        try {
            try {
                try {
                    Class<?> cls2 = Class.forName("sun.misc.Unsafe");
                    Field declaredField = cls2.getDeclaredField("theUnsafe");
                    declaredField.setAccessible(true);
                    rVar = new o(declaredField.get(null), cls2.getMethod("allocateInstance", Class.class));
                } catch (Exception unused) {
                    rVar = new com.google.gson.internal.r();
                }
            } catch (Exception unused2) {
                Method declaredMethod = ObjectInputStream.class.getDeclaredMethod("newInstance", Class.class, Class.class);
                declaredMethod.setAccessible(true);
                rVar = new com.google.gson.internal.q(declaredMethod);
            }
        } catch (Exception unused3) {
            Method declaredMethod2 = ObjectStreamClass.class.getDeclaredMethod("getConstructorId", Class.class);
            declaredMethod2.setAccessible(true);
            int iIntValue = ((Integer) declaredMethod2.invoke(null, Object.class)).intValue();
            Method declaredMethod3 = ObjectStreamClass.class.getDeclaredMethod("newInstance", Class.class, Integer.TYPE);
            declaredMethod3.setAccessible(true);
            rVar = new com.google.gson.internal.p(declaredMethod3, iIntValue);
        }
        this.a = rVar;
    }

    public c(com.quizlet.data.interactor.school.b bVar) {
        this.c = bVar;
        this.b = new AtomicBoolean(false);
        this.a = ((androidx.camera.camera2.internal.C) bVar.c).d.schedule(new RunnableC0146x(this, 1), 2000L, TimeUnit.MILLISECONDS);
    }
}

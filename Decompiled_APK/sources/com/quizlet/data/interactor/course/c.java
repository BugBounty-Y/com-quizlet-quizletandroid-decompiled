package com.quizlet.data.interactor.course;

import android.database.Cursor;
import android.database.sqlite.SQLiteException;
import androidx.camera.core.impl.EnumC0174m;
import androidx.camera.core.impl.EnumC0175n;
import androidx.camera.core.impl.EnumC0176o;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.v0;
import androidx.work.impl.model.n;
import androidx.work.impl.model.v;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.measurement.T0;
import com.google.android.gms.internal.measurement.U0;
import com.google.android.gms.measurement.internal.C3870h;
import com.google.android.gms.measurement.internal.C3874j;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.M;
import com.google.android.gms.measurement.internal.Y;
import io.reactivex.rxjava3.core.p;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements InterfaceC0177p, io.reactivex.rxjava3.functions.h {
    public long a;
    public final Object b;
    public final Object c;

    public c(com.google.firebase.crashlytics.internal.settings.b bVar, long j, p pVar) {
        this.b = bVar;
        this.a = j;
        this.c = pVar;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public long a() {
        InterfaceC0177p interfaceC0177p = (InterfaceC0177p) this.b;
        if (interfaceC0177p != null) {
            return interfaceC0177p.a();
        }
        long j = this.a;
        if (j != -1) {
            return j;
        }
        throw new IllegalStateException("No timestamp is available.");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List teacherClassIds = (List) obj;
        Intrinsics.checkNotNullParameter(teacherClassIds, "teacherClassIds");
        if (teacherClassIds.isEmpty()) {
            return p.f(Boolean.FALSE);
        }
        v vVar = (v) ((com.google.firebase.crashlytics.internal.settings.b) this.b).b;
        p stopToken = (p) this.c;
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((androidx.work.impl.model.c) vVar.c).c(stopToken, new com.quizlet.data.interactor.classmembership.a(vVar, this.a, 1)).g(new com.quizlet.infra.legacysyncengine.features.properties.e(teacherClassIds));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public v0 b() {
        return (v0) this.c;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0176o c() {
        InterfaceC0177p interfaceC0177p = (InterfaceC0177p) this.b;
        return interfaceC0177p != null ? interfaceC0177p.c() : EnumC0176o.a;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0174m d() {
        InterfaceC0177p interfaceC0177p = (InterfaceC0177p) this.b;
        return interfaceC0177p != null ? interfaceC0177p.d() : EnumC0174m.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(long r17, long r19, kotlin.coroutines.jvm.internal.c r21) throws java.lang.Throwable {
        /*
            r16 = this;
            r1 = r16
            r0 = r21
            boolean r2 = r0 instanceof com.quizlet.data.interactor.course.b
            if (r2 == 0) goto L17
            r2 = r0
            com.quizlet.data.interactor.course.b r2 = (com.quizlet.data.interactor.course.b) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L17
            int r3 = r3 - r4
            r2.m = r3
            goto L1c
        L17:
            com.quizlet.data.interactor.course.b r2 = new com.quizlet.data.interactor.course.b
            r2.<init>(r1, r0)
        L1c:
            java.lang.Object r0 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 1
            if (r4 == 0) goto L37
            if (r4 != r5) goto L2f
            com.quizlet.data.interactor.course.c r2 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r0)     // Catch: java.lang.Exception -> L2d
            goto L5c
        L2d:
            r0 = move-exception
            goto L65
        L2f:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            java.lang.Object r0 = r1.b     // Catch: java.lang.Exception -> L63
            r14 = r0
            androidx.work.impl.model.n r14 = (androidx.work.impl.model.n) r14     // Catch: java.lang.Exception -> L63
            long r11 = r1.a     // Catch: java.lang.Exception -> L63
            r2.j = r1     // Catch: java.lang.Exception -> L63
            r2.m = r5     // Catch: java.lang.Exception -> L63
            com.quizlet.remote.model.course.e r6 = new com.quizlet.remote.model.course.e     // Catch: java.lang.Exception -> L63
            r15 = 0
            r13 = 0
            r7 = r17
            r9 = r19
            r6.<init>(r7, r9, r11, r13, r14, r15)     // Catch: java.lang.Exception -> L63
            java.lang.Object r0 = r14.d     // Catch: java.lang.Exception -> L63
            kotlinx.coroutines.y r0 = (kotlinx.coroutines.AbstractC5040y) r0     // Catch: java.lang.Exception -> L63
            java.lang.Object r0 = kotlinx.coroutines.E.J(r0, r6, r2)     // Catch: java.lang.Exception -> L63
            if (r0 != r3) goto L5b
            return r3
        L5b:
            r2 = r1
        L5c:
            com.quizlet.data.model.d0 r0 = (com.quizlet.data.model.AbstractC4119d0) r0     // Catch: java.lang.Exception -> L2d
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        L61:
            r2 = r1
            goto L65
        L63:
            r0 = move-exception
            goto L61
        L65:
            java.lang.Object r2 = r2.c
            org.slf4j.b r2 = (org.slf4j.b) r2
            java.lang.String r3 = "Exception in the CreateNewCourseMembershipUseCase while creating new course membership."
            r2.m(r3)
            com.quizlet.data.repository.course.exceptions.CreateNewCourseMembershipException r2 = new com.quizlet.data.repository.course.exceptions.CreateNewCourseMembershipException
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            java.lang.String r4 = "Could not create course membership. "
            r3.<init>(r4)
            r3.append(r0)
            java.lang.String r0 = r3.toString()
            r2.<init>(r0)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.course.c.f(long, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0175n g() {
        InterfaceC0177p interfaceC0177p = (InterfaceC0177p) this.b;
        return interfaceC0177p != null ? interfaceC0177p.g() : EnumC0175n.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v2, types: [java.util.List] */
    public List h() {
        ArrayList arrayList;
        C3874j c3874j = (C3874j) this.c;
        ArrayList arrayList2 = new ArrayList();
        String strValueOf = String.valueOf(this.a);
        String str = (String) this.b;
        Cursor cursorQuery = null;
        try {
            try {
                cursorQuery = c3874j.O0().query("raw_events", new String[]{"rowid", "name", "timestamp", "metadata_fingerprint", "data", "realtime"}, "app_id = ? and rowid > ?", new String[]{str, strValueOf}, null, null, "rowid", "1000");
                if (cursorQuery.moveToFirst()) {
                    do {
                        long j = cursorQuery.getLong(0);
                        long j2 = cursorQuery.getLong(3);
                        boolean z = cursorQuery.getLong(5) == 1;
                        byte[] blob = cursorQuery.getBlob(4);
                        if (j > this.a) {
                            this.a = j;
                        }
                        try {
                            T0 t0 = (T0) M.y0(U0.r(), blob);
                            String string = cursorQuery.getString(1);
                            if (string == null) {
                                string = "";
                            }
                            t0.h();
                            U0.z((U0) t0.b, string);
                            long j3 = cursorQuery.getLong(2);
                            t0.h();
                            U0.C(j3, (U0) t0.b);
                            arrayList2.add(new C3870h(j, j2, z, (U0) t0.f()));
                        } catch (IOException e) {
                            I i = ((Y) c3874j.b).i;
                            Y.k(i);
                            i.g.h("Data loss. Failed to merge raw event. appId", I.a0(str), e);
                        }
                    } while (cursorQuery.moveToNext());
                } else {
                    arrayList = Collections.EMPTY_LIST;
                }
            } catch (SQLiteException e2) {
                I i2 = ((Y) c3874j.b).i;
                Y.k(i2);
                i2.g.h("Data loss. Error querying raw events batch. appId", I.a0(str), e2);
                arrayList = arrayList2;
            }
            return arrayList;
        } finally {
            if (0 != 0) {
                cursorQuery.close();
            }
        }
    }

    public c(C3874j c3874j, String str) {
        this.c = c3874j;
        u.e(str);
        this.b = str;
        this.a = -1L;
    }

    public c(C3874j c3874j, String str, long j) {
        this.c = c3874j;
        u.e(str);
        this.b = str;
        this.a = c3874j.K0("select rowid from raw_events where app_id = ? and timestamp < ? order by rowid desc limit 1", new String[]{str, String.valueOf(j)}, -1L);
    }

    public c(n repository, org.slf4j.b logger, long j) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = repository;
        this.c = logger;
        this.a = j;
    }

    public c(InterfaceC0177p interfaceC0177p, v0 v0Var, long j) {
        this.b = interfaceC0177p;
        this.c = v0Var;
        this.a = j;
    }
}

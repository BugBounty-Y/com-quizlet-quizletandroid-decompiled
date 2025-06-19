package com.quizlet.edgy.ui.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P6;
import com.quizlet.data.model.School;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes2.dex */
public final class M extends w0 {
    public final com.onetrust.otpublishers.headless.UI.fragment.q b;
    public final com.google.firebase.messaging.p c;
    public final com.quizlet.data.interactor.school.e d;
    public final com.quizlet.data.interactor.course.e e;
    public final com.quizlet.data.interactor.school.b f;
    public final com.quizlet.data.interactor.course.c g;
    public final com.quizlet.data.interactor.course.a h;
    public final com.quizlet.data.repository.qclass.c i;
    public final com.quizlet.data.interactor.course.a j;
    public com.quizlet.edgy.ui.recyclerview.adapter.i k;
    public String l;
    public String m;
    public final ArrayList n;
    public final ArrayList o;
    public final s0 p;
    public final d0 q;
    public final Y r;
    public final d0 s;
    public final Y t;
    public final C4203d u;
    public y0 v;
    public y0 w;

    public M(com.onetrust.otpublishers.headless.UI.fragment.q searchSchoolsUseCase, com.google.firebase.messaging.p searchCoursesUseCase, com.quizlet.data.interactor.school.e deleteSchoolMembershipUseCase, com.quizlet.data.interactor.course.e deleteCourseMembershipUseCase, com.quizlet.data.interactor.school.b createNewSchoolMembershipUseCase, com.quizlet.data.interactor.course.c createNewCourseMembershipUseCase, com.quizlet.data.interactor.school.f getPopularSchoolsUseCase, com.quizlet.data.interactor.course.a courseMembershipUseCase, com.quizlet.data.repository.qclass.c schoolMembershipUseCase, com.quizlet.data.interactor.course.a edgyLogger) {
        Intrinsics.checkNotNullParameter(searchSchoolsUseCase, "searchSchoolsUseCase");
        Intrinsics.checkNotNullParameter(searchCoursesUseCase, "searchCoursesUseCase");
        Intrinsics.checkNotNullParameter(deleteSchoolMembershipUseCase, "deleteSchoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(deleteCourseMembershipUseCase, "deleteCourseMembershipUseCase");
        Intrinsics.checkNotNullParameter(createNewSchoolMembershipUseCase, "createNewSchoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(createNewCourseMembershipUseCase, "createNewCourseMembershipUseCase");
        Intrinsics.checkNotNullParameter(getPopularSchoolsUseCase, "getPopularSchoolsUseCase");
        Intrinsics.checkNotNullParameter(courseMembershipUseCase, "courseMembershipUseCase");
        Intrinsics.checkNotNullParameter(schoolMembershipUseCase, "schoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(edgyLogger, "edgyLogger");
        this.b = searchSchoolsUseCase;
        this.c = searchCoursesUseCase;
        this.d = deleteSchoolMembershipUseCase;
        this.e = deleteCourseMembershipUseCase;
        this.f = createNewSchoolMembershipUseCase;
        this.g = createNewCourseMembershipUseCase;
        this.h = courseMembershipUseCase;
        this.i = schoolMembershipUseCase;
        this.j = edgyLogger;
        List listJ = kotlin.collections.B.j(com.quizlet.data.interactor.school.f.a, com.quizlet.data.interactor.school.f.b, com.quizlet.data.interactor.school.f.c, com.quizlet.data.interactor.school.f.d, com.quizlet.data.interactor.school.f.e);
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listJ, 10));
        Iterator it2 = listJ.iterator();
        while (it2.hasNext()) {
            arrayList.add(P6.a((School) it2.next()));
        }
        this.n = arrayList;
        this.o = new ArrayList();
        this.p = e0.c(C4211l.a);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.q = d0VarB;
        this.r = new Y(d0VarB);
        d0 d0VarB2 = e0.b(0, 0, null, 7);
        this.s = d0VarB2;
        this.t = new Y(d0VarB2);
        C4203d c4203d = new C4203d(this);
        this.u = c4203d;
        this.j.j("edgy_data_flow_presented", "info", "edgy_data", false);
        kotlinx.coroutines.E.A(p0.j(this), c4203d, null, new C(this, null), 2);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r9v1, types: [java.lang.Iterable, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable A(com.quizlet.edgy.ui.viewmodel.M r8, java.lang.String r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            boolean r0 = r10 instanceof com.quizlet.edgy.ui.viewmodel.H
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.edgy.ui.viewmodel.H r0 = (com.quizlet.edgy.ui.viewmodel.H) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.edgy.ui.viewmodel.H r0 = new com.quizlet.edgy.ui.viewmodel.H
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 10
            r4 = 1
            if (r2 == 0) goto L33
            if (r2 != r4) goto L2b
            java.util.ArrayList r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L6c
        L2b:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r10 = r8.o
            java.util.ArrayList r2 = new java.util.ArrayList
            int r5 = kotlin.collections.C.q(r10, r3)
            r2.<init>(r5)
            java.util.Iterator r10 = r10.iterator()
        L45:
            boolean r5 = r10.hasNext()
            if (r5 == 0) goto L5c
            java.lang.Object r5 = r10.next()
            com.quizlet.edgy.ui.recyclerview.adapter.d r5 = (com.quizlet.edgy.ui.recyclerview.adapter.d) r5
            long r5 = r5.a
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            r2.add(r7)
            goto L45
        L5c:
            r0.j = r2
            r0.m = r4
            r10 = 20
            com.google.firebase.messaging.p r8 = r8.c
            java.lang.Object r10 = r8.u(r9, r10, r0)
            if (r10 != r1) goto L6b
            return r1
        L6b:
            r8 = r2
        L6c:
            com.quizlet.data.model.L r10 = (com.quizlet.data.model.L) r10
            java.lang.Object r9 = r10.a
            java.util.ArrayList r10 = new java.util.ArrayList
            r10.<init>()
            java.util.Iterator r9 = r9.iterator()
        L79:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto L97
            java.lang.Object r0 = r9.next()
            r1 = r0
            com.quizlet.data.model.Course r1 = (com.quizlet.data.model.Course) r1
            long r1 = r1.a
            java.lang.Long r4 = new java.lang.Long
            r4.<init>(r1)
            boolean r1 = r8.contains(r4)
            if (r1 != 0) goto L79
            r10.add(r0)
            goto L79
        L97:
            java.util.ArrayList r8 = new java.util.ArrayList
            int r9 = kotlin.collections.C.q(r10, r3)
            r8.<init>(r9)
            java.util.Iterator r9 = r10.iterator()
        La4:
            boolean r10 = r9.hasNext()
            if (r10 == 0) goto Lb8
            java.lang.Object r10 = r9.next()
            com.quizlet.data.model.Course r10 = (com.quizlet.data.model.Course) r10
            com.quizlet.edgy.ui.recyclerview.adapter.g r10 = com.google.android.gms.internal.mlkit_vision_document_scanner.O6.b(r10)
            r8.add(r10)
            goto La4
        Lb8:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.M.A(com.quizlet.edgy.ui.viewmodel.M, java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.edgy.ui.viewmodel.M r4, kotlin.coroutines.jvm.internal.c r5) throws com.quizlet.data.repository.school.exceptions.SchoolMembershipException {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof com.quizlet.edgy.ui.viewmodel.L
            if (r0 == 0) goto L16
            r0 = r5
            com.quizlet.edgy.ui.viewmodel.L r0 = (com.quizlet.edgy.ui.viewmodel.L) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.edgy.ui.viewmodel.L r0 = new com.quizlet.edgy.ui.viewmodel.L
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.edgy.ui.viewmodel.M r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L44
        L2c:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            r0.m = r3
            com.quizlet.data.repository.qclass.c r5 = r4.i
            java.lang.Object r5 = r5.m(r0)
            if (r5 != r1) goto L44
            return r1
        L44:
            com.quizlet.data.model.w1 r5 = (com.quizlet.data.model.C4177w1) r5
            if (r5 == 0) goto L4f
            com.quizlet.data.model.School r5 = r5.a
            com.quizlet.edgy.ui.recyclerview.adapter.i r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.P6.a(r5)
            goto L50
        L4f:
            r5 = 0
        L50:
            if (r5 != 0) goto L56
            r4.F(r3)
            goto L59
        L56:
            r4.E(r5, r3)
        L59:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.M.B(com.quizlet.edgy.ui.viewmodel.M, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void C() {
        com.quizlet.edgy.ui.recyclerview.adapter.i iVar = this.k;
        if (iVar != null) {
            kotlinx.coroutines.E.A(p0.j(this), this.u, null, new B(iVar, this, null), 2);
        } else {
            F(true);
            this.l = null;
            Unit unit = Unit.a;
        }
    }

    public final void D() {
        s0 s0Var;
        Object value;
        com.quizlet.edgy.ui.recyclerview.adapter.i iVar = this.k;
        if (iVar != null) {
            do {
                s0Var = this.p;
                value = s0Var.getValue();
            } while (!s0Var.k(value, new C4206g(iVar, this.o)));
            Unit unit = Unit.a;
        }
    }

    public final void E(com.quizlet.edgy.ui.recyclerview.adapter.i iVar, boolean z) {
        s0 s0Var;
        Object value;
        if (z) {
            this.j.j("edgy_data_course_screen_seen", "info", "edgy_data", false);
        }
        this.k = iVar;
        do {
            s0Var = this.p;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new o(iVar)));
    }

    public final void F(boolean z) {
        s0 s0Var;
        Object value;
        this.j.j("edgy_data_school_screen_seen", "info", "edgy_data", false);
        do {
            s0Var = this.p;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new q(z ? this.n : null)));
    }
}

package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.J0;
import com.google.firebase.messaging.p;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.h0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class o extends w0 implements b {
    public final com.google.firebase.crashlytics.internal.common.j b;
    public final com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i c;
    public final p d;
    public final q e;
    public final com.quizlet.data.repository.widget.b f;
    public final FolderLogger g;
    public final s0 h;
    public final Z i;
    public final d0 j;
    public final d0 k;
    public y0 l;
    public com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f m;
    public String n;
    public String o;

    public o(com.google.firebase.crashlytics.internal.common.j searchSchoolUseCase, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i schoolMembershipUseCase, p searchCourseVMUseCase, q createCourseVMUseCase, com.quizlet.data.repository.widget.b schoolCourseSuggestionsVMUseCase, FolderLogger folderEventLogger) {
        Intrinsics.checkNotNullParameter(searchSchoolUseCase, "searchSchoolUseCase");
        Intrinsics.checkNotNullParameter(schoolMembershipUseCase, "schoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(searchCourseVMUseCase, "searchCourseVMUseCase");
        Intrinsics.checkNotNullParameter(createCourseVMUseCase, "createCourseVMUseCase");
        Intrinsics.checkNotNullParameter(schoolCourseSuggestionsVMUseCase, "schoolCourseSuggestionsVMUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.b = searchSchoolUseCase;
        this.c = schoolMembershipUseCase;
        this.d = searchCourseVMUseCase;
        this.e = createCourseVMUseCase;
        this.f = schoolCourseSuggestionsVMUseCase;
        this.g = folderEventLogger;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a aVar = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.e;
        s0 s0VarC = e0.c(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p((List) null, aVar, false, 29));
        this.h = s0VarC;
        this.i = e0.x(new J0(new n(this, null), s0VarC), p0.j(this), h0.a(3), new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p((List) null, aVar, false, 29));
        this.j = e0.b(0, 0, null, 7);
        this.k = e0.b(0, 0, null, 7);
        this.n = "";
        this.o = "";
    }

    public static ArrayList C(List list, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar, boolean z) {
        boolean z2;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f eVar2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) it2.next();
            if ((eVar2 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) && eVar2.a == eVar.a) {
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar3 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) eVar2;
                String schoolTitle = eVar3.g;
                Intrinsics.checkNotNullParameter(schoolTitle, "schoolTitle");
                String schoolDescription = eVar3.h;
                Intrinsics.checkNotNullParameter(schoolDescription, "schoolDescription");
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.d schoolType = eVar3.i;
                Intrinsics.checkNotNullParameter(schoolType, "schoolType");
                String schoolSearchSessionId = eVar3.k;
                Intrinsics.checkNotNullParameter(schoolSearchSessionId, "schoolSearchSessionId");
                z2 = z;
                eVar2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e(eVar3.f, schoolTitle, schoolDescription, schoolType, z2, schoolSearchSessionId);
            } else {
                z2 = z;
            }
            arrayList.add(eVar2);
            z = z2;
        }
        return arrayList;
    }

    public static void F(o oVar, List list, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a aVar, int i) {
        String str;
        if ((i & 1) != 0) {
            list = K.a;
        }
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar = oVar.m;
        if (fVar == null || (str = fVar.b) == null) {
            str = "";
        }
        oVar.E(list, aVar, str, false);
    }

    public static void G(o oVar, List list, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a aVar, boolean z, boolean z2, int i) {
        Object value;
        if ((i & 1) != 0) {
            list = K.a;
        }
        if ((i & 8) != 0) {
            z = false;
        }
        if ((i & 16) != 0) {
            z2 = false;
        }
        s0 s0Var = oVar.h;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p(list, aVar, z2, z)));
        if (aVar == com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b || aVar == com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.e) {
            oVar.g.o();
        }
    }

    public final void A(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar) {
        F(this, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.a, 13);
        if (fVar != null) {
            E.A(p0.j(this), null, null, new f(this, fVar, null), 3);
        } else {
            F(this, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.e, 13);
            Unit unit = Unit.a;
        }
    }

    public final void B(boolean z) {
        G(this, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.a, false, false, 29);
        E.A(p0.j(this), null, null, new h(this, z, null), 3);
    }

    public final void D(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.n event) {
        s0 s0Var;
        Object value;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q qVar;
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.l) {
            String str = ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.l) event).a;
            this.n = str;
            y0 y0Var = this.l;
            if (y0Var != null) {
                y0Var.j(null);
            }
            G(this, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.a, false, false, 29);
            this.l = E.A(p0.j(this), null, null, new k(this, str, null), 3);
            return;
        }
        if (event instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.i) {
            String str2 = ((com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.i) event).a;
            this.o = str2;
            y0 y0Var2 = this.l;
            if (y0Var2 != null) {
                y0Var2.j(null);
            }
            F(this, null, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.a, 13);
            this.l = E.A(p0.j(this), null, null, new j(this, str2, null), 3);
            return;
        }
        if (event instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.k) {
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.k kVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.k) event;
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar = kVar.a;
            boolean z = fVar instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c;
            long j = kVar.b;
            if (z) {
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c cVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c) fVar;
                String str3 = this.o;
                this.g.w(cVar.a, Long.valueOf(j), str3, cVar.e);
                E.A(p0.j(this), null, null, new i(this, cVar, null), 3);
                return;
            }
            if (!(fVar instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) fVar;
            do {
                s0Var = this.h;
                value = s0Var.getValue();
                qVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q) value;
            } while (!s0Var.k(value, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.p(C(qVar.getResults(), eVar, true), com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b, qVar.c(), 20)));
            String str4 = this.n;
            this.g.x(eVar.a, Long.valueOf(j), str4, eVar.e);
            E.A(p0.j(this), null, null, new m(this, eVar, null), 3);
            return;
        }
        if (event instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.m) {
            this.m = null;
            B(false);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.g.a)) {
            E.A(p0.j(this), null, null, new d(this, null), 3);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.h.a)) {
            E.A(p0.j(this), null, null, new e(this, null), 3);
            return;
        }
        if (!(event instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.j)) {
            throw new NoWhenBranchMatchedException();
        }
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.j jVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.j) event;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f fVar2 = jVar.a;
        boolean z2 = fVar2 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c;
        long j2 = jVar.b;
        if (z2) {
            this.g.f(fVar2.a, j2, this.o, fVar2.e);
        } else {
            if (!(fVar2 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e)) {
                throw new NoWhenBranchMatchedException();
            }
            this.g.H(fVar2.a, j2, this.n, fVar2.e);
        }
    }

    public final void E(List list, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a aVar, String str, boolean z) {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.h;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.o(list, aVar, str, z)));
        if (aVar == com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b) {
            this.g.n();
        }
    }
}

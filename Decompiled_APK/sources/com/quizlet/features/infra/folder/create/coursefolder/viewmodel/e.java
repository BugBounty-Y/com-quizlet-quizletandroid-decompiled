package com.quizlet.features.infra.folder.create.coursefolder.viewmodel;

import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.features.infra.folder.create.coursefolder.data.k;
import com.quizlet.features.infra.folder.create.coursefolder.data.l;
import com.quizlet.features.infra.folder.create.coursefolder.data.m;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends w0 implements f {
    public final i b;
    public final FolderLogger c;
    public final com.quizlet.data.repository.course.membership.c d;
    public boolean e;
    public boolean f;
    public boolean g;
    public boolean h;
    public String i;
    public Long j;
    public final s0 k;
    public long l;
    public long m;
    public com.quizlet.features.infra.folder.create.data.b n;
    public final d0 o;
    public final d0 p;

    public e(i schoolMembershipUseCase, FolderLogger folderEventLogger, com.quizlet.data.repository.course.membership.c courseFolderFeatureFlag) {
        Intrinsics.checkNotNullParameter(schoolMembershipUseCase, "schoolMembershipUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(courseFolderFeatureFlag, "courseFolderFeatureFlag");
        this.b = schoolMembershipUseCase;
        this.c = folderEventLogger;
        this.d = courseFolderFeatureFlag;
        this.i = "";
        this.k = e0.c(l.a);
        this.n = com.quizlet.features.infra.folder.create.data.b.a;
        this.o = e0.b(0, 0, null, 7);
        this.p = e0.b(0, 0, null, 7);
    }

    public final boolean A() {
        return this.e ? this.i.length() > 0 && this.f : this.i.length() > 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00fe  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void B(com.quizlet.features.infra.folder.create.coursefolder.data.j r18) {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.viewmodel.e.B(com.quizlet.features.infra.folder.create.coursefolder.data.j):void");
    }

    public final void C(String str, String str2, boolean z) {
        boolean zA = A();
        while (true) {
            s0 s0Var = this.k;
            Object value = s0Var.getValue();
            String str3 = str;
            String str4 = str2;
            boolean z2 = z;
            if (s0Var.k(value, new k(str3, this.e, str4, z2, this.i, zA))) {
                break;
            }
            str = str3;
            str2 = str4;
            z = z2;
        }
        com.quizlet.features.infra.folder.create.data.b bVar = this.n;
        com.quizlet.features.infra.folder.create.data.b bVar2 = com.quizlet.features.infra.folder.create.data.b.a;
        FolderLogger folderLogger = this.c;
        if (bVar == bVar2) {
            folderLogger.i();
        } else {
            folderLogger.q(this.j);
        }
    }

    public final void D(String str, boolean z) {
        s0 s0Var;
        Object value;
        Object objD;
        String str2;
        boolean zA = A();
        do {
            s0Var = this.k;
            value = s0Var.getValue();
            objD = (m) value;
            k kVar = objD instanceof k ? (k) objD : null;
            String str3 = "";
            if (!z) {
                if (str.length() != 0) {
                    str3 = str;
                } else if (kVar != null && (str2 = kVar.c) != null) {
                    str3 = str2;
                }
            }
            String str4 = str3;
            if (kVar != null) {
                objD = k.d(kVar, null, this.e, str4, this.i, zA, 9);
            }
        } while (!s0Var.k(value, objD));
    }
}

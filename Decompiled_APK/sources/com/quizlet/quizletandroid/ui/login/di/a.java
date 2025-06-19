package com.quizlet.quizletandroid.ui.login.di;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.CreatedFolderStudyMaterial;
import com.quizlet.data.model.D1;
import com.quizlet.data.model.DeletedFolderStudyMaterial;
import com.quizlet.data.model.E1;
import com.quizlet.data.model.K;
import com.quizlet.data.model.p2;
import com.quizlet.generated.enums.x1;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import com.quizlet.remote.mapper.base.b;
import com.quizlet.remote.model.course.c;
import com.quizlet.remote.model.course.memberships.CourseInstanceResponse;
import com.quizlet.remote.model.course.memberships.RemoteCourseInstance;
import com.quizlet.remote.model.folderstudymaterial.RemoteFolderStudyMaterial;
import com.quizlet.remote.model.selectedterm.RemoteSelectedTerm;
import com.quizlet.remote.model.selectedterm.RemoteUnselectedTerm;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, com.quizlet.remote.mapper.base.a, b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static D1 a(com.quizlet.remote.model.selectedterm.a remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        if (!(remote instanceof RemoteSelectedTerm)) {
            if (!(remote instanceof RemoteUnselectedTerm)) {
                throw new NoWhenBranchMatchedException();
            }
            RemoteUnselectedTerm remoteUnselectedTerm = (RemoteUnselectedTerm) remote;
            return new p2(remoteUnselectedTerm.a, remoteUnselectedTerm.b, remoteUnselectedTerm.c);
        }
        RemoteSelectedTerm remoteSelectedTerm = (RemoteSelectedTerm) remote;
        return new E1(remoteSelectedTerm.a, remoteSelectedTerm.b, remoteSelectedTerm.d, remoteSelectedTerm.c);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        CourseInstanceResponse remote = (CourseInstanceResponse) obj;
        Intrinsics.checkNotNullParameter(remote, "response");
        Intrinsics.checkNotNullParameter(remote, "remote");
        List<RemoteCourseInstance> list = remote.a;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (RemoteCourseInstance remoteCourseInstance : list) {
            arrayList.add(new K(com.quizlet.remote.model.school.a.a(remoteCourseInstance.a), c.a(remoteCourseInstance.b)));
        }
        return arrayList;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        Object createdFolderStudyMaterial;
        switch (this.a) {
            case 2:
                RemoteFolderStudyMaterial remote = (RemoteFolderStudyMaterial) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                boolean zB = Intrinsics.b(remote.i, Boolean.TRUE);
                Integer num = remote.d;
                String str = remote.c;
                Long l = remote.b;
                Long l2 = remote.a;
                if (zB) {
                    if (l2 == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    long jLongValue = l2.longValue();
                    if (l == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    long jLongValue2 = l.longValue();
                    if (str == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    x1 x1Var = y1.Companion;
                    if (num == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    int iIntValue = num.intValue();
                    x1Var.getClass();
                    createdFolderStudyMaterial = new DeletedFolderStudyMaterial(jLongValue, jLongValue2, str, x1.a(iIntValue));
                } else {
                    if (l2 == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    long jLongValue3 = l2.longValue();
                    if (l == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    long jLongValue4 = l.longValue();
                    if (str == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    x1 x1Var2 = y1.Companion;
                    if (num == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    int iIntValue2 = num.intValue();
                    x1Var2.getClass();
                    y1 y1VarA = x1.a(iIntValue2);
                    Long l3 = remote.e;
                    if (l3 == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    long jLongValue5 = l3.longValue();
                    Long l4 = remote.g;
                    if (l4 == null) {
                        throw new IllegalArgumentException("Required value was null.");
                    }
                    createdFolderStudyMaterial = new CreatedFolderStudyMaterial(jLongValue3, jLongValue4, str, y1VarA, jLongValue5, l4.longValue());
                }
                return createdFolderStudyMaterial;
            default:
                return a((com.quizlet.remote.model.selectedterm.a) obj);
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 2:
                return S.f(this, list);
            default:
                return T.f(this, list);
        }
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        D1 data = (D1) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        if (!(data instanceof E1)) {
            if (!(data instanceof p2)) {
                throw new NoWhenBranchMatchedException();
            }
            p2 p2Var = (p2) data;
            return new RemoteUnselectedTerm(p2Var.a, p2Var.b, p2Var.c);
        }
        E1 e1 = (E1) data;
        return new RemoteSelectedTerm(e1.a, e1.b, e1.d, e1.c);
    }

    public a(n nVar) {
        this.a = 1;
    }
}
